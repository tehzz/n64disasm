use crate::disasm::{memmap::Section, pass1::BlockLoadedSections};
use err_derive::Error;
use std::convert::TryInto;
use std::fmt;
use std::ops::Range;

#[derive(Debug, Error)]
pub enum DataParseErr {
    #[error(display = "Data buffer to parse was not a multiple of 4 bytes")]
    BadDataLen,
    #[error(display = "Data start RAM address was not 4 byte aligned")]
    BadDataAlign,
    #[error(display = "Illegal SM combination at {:x}: {}", _0, _1)]
    SmFail(u32, String),
}

type DpResult<T> = Result<T, DataParseErr>;

// move to a parsedata module
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParsedData<'rom> {
    Float(u32),         // hex of float
    Double(u64),        // hex of double
    Asciiz(&'rom str),  // str view of rom data; doesn't include \0
    JmpTbl(Box<[u32]>), // entries address
    Ptr(u32),           // standard pointer
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DataEntry<'rom> {
    addr: u32,
    data: ParsedData<'rom>,
}

#[derive(Debug)]
pub struct FindDataIter<'a, 'rom> {
    buffer: &'rom [u8], // full data slice to parse
    start_ram: u32,     // start of full data slice
    csr: &'rom [u8],    // unparsed slice of buffer
    at: u32,            // ram address of start of csr
    vram: Range<u32>,
    sections: &'a BlockLoadedSections,
    yielded: Option<DataEntry<'rom>>,
    state: State,
}

impl<'a, 'rom> Iterator for FindDataIter<'a, 'rom> {
    type Item = DataEntry<'rom>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.is_finished() {
            let event = self.run();
            self.state = self.state.next(event);

            if self.yielded.is_some() {
                break;
            }
        }

        self.yielded.take()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum State {
    Checking,
    AddPtr(u32, u32),
    AddTwoPtr([(u32, u32); 2]),
    StartJmpTbl(u32, u32),
    GrowJmpTbl(u32, Option<Vec<u32>>),
    EndJmpTbl(u32, Option<Vec<u32>>),
    EndJmpTblAndPtr((u32, Option<Vec<u32>>), (u32, u32)),
    EndJmpTblAndAscii((u32, Option<Vec<u32>>), u32),
    ParseAscii(u32), //start offset
    PtrThenAscii((u32, u32), u32),
    Failure, // TODO: put error in here
    Finished,
}

#[derive(Debug, Copy, Clone)]
enum Event {
    Nothing,
    Issue,
    EndOfData,
    YieldData,
    FoundTextPtr(u32, u32), // offset, pointer value
    FoundPtr(u32, u32),     // offset, pointer value
    FoundAscii(u32),        // offset
    BufferedPtr(u32, u32),  // offset, length
    BufferedAscii(u32),     // offset
}

impl State {
    fn next(&mut self, event: Event) -> Self {
        use Event::*;
        use State::*;

        match (self, event) {
            (Checking, Nothing) => Checking,
            // Buffered data to process
            (_, BufferedPtr(offset, ptr)) => AddPtr(offset, ptr),
            (_, BufferedAscii(offset)) => ParseAscii(offset),
            // Single pointer to outside of this sections .text
            (Checking, FoundPtr(offset, ptr)) => AddPtr(offset, ptr),
            // Single pointer to this sections .text
            (Checking, FoundTextPtr(offset, ptr)) => StartJmpTbl(offset, ptr),
            (StartJmpTbl(offset, ptr), Nothing) => AddPtr(*offset, *ptr),
            (StartJmpTbl(off, ptr), FoundPtr(off2, ptr2)) => {
                AddTwoPtr([(*off, *ptr), (off2, ptr2)])
            }
            (StartJmpTbl(ptr_off, ptr), FoundAscii(str_off)) => {
                // not a jump table pointer followed by text
                PtrThenAscii((*ptr_off, *ptr), str_off)
            }
            (StartJmpTbl(offset, ptr), FoundTextPtr(_, ptr2)) => {
                GrowJmpTbl(*offset, Some(vec![*ptr, ptr2]))
            }
            (GrowJmpTbl(offset, ref mut tbl), Nothing) => EndJmpTbl(*offset, tbl.take()),
            (GrowJmpTbl(offset, ref mut tbl), EndOfData) => EndJmpTbl(*offset, tbl.take()),
            (GrowJmpTbl(offset, ref mut tbl), FoundPtr(off2, ptr2)) => {
                EndJmpTblAndPtr((*offset, tbl.take()), (off2, ptr2))
            }
            (GrowJmpTbl(offset, ref mut tbl), FoundAscii(str_off)) => {
                EndJmpTblAndAscii((*offset, tbl.take()), str_off)
            }
            (GrowJmpTbl(offset, ref mut tbl), FoundTextPtr(_, ptr)) => {
                let mut tbl = tbl.take().unwrap();
                tbl.push(ptr);

                GrowJmpTbl(*offset, Some(tbl))
            }
            // Ascii parsing
            (Checking, FoundAscii(offset)) => ParseAscii(offset),

            // end conditions
            (_, EndOfData) => Finished,
            (Finished, _) => Finished,

            // loop conditions
            (_, YieldData) => Checking,
            (_, Nothing) => Checking,

            // Error
            (s, e) => Failure,
        }
    }
}

impl<'a, 'rom> FindDataIter<'a, 'rom> {
    pub fn new(
        buffer: &'rom [u8],
        start_ram: u32,
        sections: &'a BlockLoadedSections,
        use_mempak: bool,
    ) -> DpResult<Self> {
        if buffer.len() % 4 != 0 {
            return Err(DataParseErr::BadDataLen);
        }
        if start_ram % 4 != 0 {
            return Err(DataParseErr::BadDataAlign);
        }

        let vram = if use_mempak {
            0x80000400..0x80800000
        } else {
            0x80000400..0x80400000
        };

        Ok(Self {
            buffer,
            start_ram,
            csr: buffer,
            at: start_ram,
            yielded: None,
            state: State::Checking,
            sections,
            vram,
        })
    }

    fn is_finished(&self) -> bool {
        match self.state {
            State::Finished => true,
            _ => false,
        }
    }

    fn run(&mut self) -> Event {
        use Event::*;
        use State::*;

        match self.state {
            Checking => self.check_next_word(),
            AddPtr(addr, ptr) => {
                let entry = DataEntry::ptr(addr, ptr);
                self.yielded = Some(entry);

                YieldData
            }
            AddTwoPtr(ptrs) => {
                let [p1, p2] = ptrs;
                let entry1 = DataEntry::tupple_ptr(&p1);
                self.yielded = Some(entry1);

                BufferedPtr(p2.0, p2.1)
            }
            StartJmpTbl(..) => self.check_next_word(),
            GrowJmpTbl(..) => self.check_next_word(),
            EndJmpTbl(addr, ref mut tbl) => {
                let tbl = tbl.take().unwrap();
                let tbl = DataEntry::jmp_tbl(addr, tbl);
                self.yielded = Some(tbl);

                YieldData
            }
            EndJmpTblAndPtr((offset, ref mut tbl), (off2, ptr2)) => {
                let tbl = tbl.take().unwrap();
                let tbl = DataEntry::jmp_tbl(offset, tbl);
                self.yielded = Some(tbl);

                BufferedPtr(off2, ptr2)
            }

            EndJmpTblAndAscii((offset, ref mut tbl), ascii_off) => {
                let tbl = tbl.take().unwrap();
                let tbl = DataEntry::jmp_tbl(offset, tbl);
                self.yielded = Some(tbl);

                BufferedAscii(ascii_off)
            }

            PtrThenAscii(ptr, ascii_off) => {
                let entry = DataEntry::tupple_ptr(&ptr);
                self.yielded = Some(entry);

                BufferedAscii(ascii_off)
            }

            ParseAscii(offset) => self.parse_ascii(offset),

            Failure => todo!(),
            Finished => Nothing,
        }
    }

    fn parse_ascii(&mut self, start_offset: u32) -> Event {
        const NB: u8 = '\0' as u8;

        let str_buffer = self.offset_to_slice(start_offset);
        let size = str_buffer
            .iter()
            .copied()
            .take_while(|b| b.is_ascii() && *b != NB)
            .count();

        if size == 0 {
            //println!("{:4}Found size zero str at {:x}", "", start_offset);
            return Event::Nothing;
        }
        //println!("{:6} possible str: {:x?} + {:?}", "",&str_buffer[..size+1], str_buffer.get(size));
        // check that the final byte was the nul terminator
        match str_buffer.get(size).copied() {
            Some(b) if b == NB => (),
            None => return Event::Nothing,
            Some(_) => return Event::Nothing,
        };
        // TODO! check that all bytes up to the next word alignment are null

        let possible_str = &str_buffer[..size];
        let ascii_str = std::str::from_utf8(possible_str).expect("valid ascii str");

        let str_end_ram = start_offset + (size as u32) + 1;
        //println!("{:4}string {:x} -> {:x}", "", start_offset, str_end_ram);
        let entry = DataEntry::asciiz(start_offset, ascii_str);

        self.yielded = Some(entry);

        if self.advance_and_word_align(str_end_ram) {
            Event::YieldData
        } else {
            Event::EndOfData
        }
    }

    /// get the full slice of data starting at RAM offset
    fn offset_to_slice(&self, offset: u32) -> &'rom [u8] {
        let idx = (offset - self.start_ram) as usize;

        &self.buffer[idx..]
    }

    fn advance_and_word_align(&mut self, to: u32) -> bool {
        let csr_ram_addr = self.at;
        let to_aligned = (to + 3) & !3;
        let new_csr_start = (to_aligned - csr_ram_addr) as usize;

        if new_csr_start < self.csr.len() {
            self.csr = &self.csr[new_csr_start..];
            self.at = to_aligned;

            true
        } else {
            false
        }
    }

    fn check_next_word(&mut self) -> Event {
        use Event::*;

        if self.csr.len() < 4 {
            return EndOfData;
        }

        let (bytes, remaining) = self.csr.split_at(4);
        let bytes: [u8; 4] = bytes.try_into().unwrap();
        let word = u32::from_be_bytes(bytes);
        let offset = self.at;

        self.csr = remaining;
        self.at += 4;

        if let Some(sec) = self.sections.find_address(word) {
            if sec.kind == Section::Text {
                FoundTextPtr(offset, word)
            } else {
                FoundPtr(offset, word)
            }
        } else if self.vram.contains(&word) {
            FoundPtr(offset, word)
        } else if word != 0 && bytes.is_ascii() {
            // `is_ascii` returns true even for nul, so ido aligned
            // strings should return true
            FoundAscii(offset)
        } else {
            Nothing
        }
    }
}

impl<'rom> DataEntry<'rom> {
    fn jmp_tbl(addr: u32, ptrs: Vec<u32>) -> Self {
        Self {
            addr,
            data: ParsedData::JmpTbl(ptrs.into()),
        }
    }
    fn ptr(addr: u32, ptr: u32) -> Self {
        Self {
            addr,
            data: ParsedData::Ptr(ptr),
        }
    }
    fn tupple_ptr(set: &(u32, u32)) -> Self {
        Self {
            addr: set.0,
            data: ParsedData::Ptr(set.1),
        }
    }
    fn asciiz(addr: u32, ptr: &'rom str) -> Self {
        Self {
            addr,
            data: ParsedData::Asciiz(ptr),
        }
    }
    pub fn float(addr: u32, val: u32) -> Self {
        Self {
            addr,
            data: ParsedData::Float(val),
        }
    }
    pub fn double(addr: u32, val: u64) -> Self {
        Self {
            addr,
            data: ParsedData::Double(val),
        }
    }
}

impl<'rom> fmt::Display for DataEntry<'rom> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsedData::*;

        match self.data {
            Float(h) => write!(f, "{}", f32::from_bits(h)),
            Double(h) => write!(f, "{}", f64::from_bits(h)),
            Asciiz(s) => write!(f, "{}", s),
            JmpTbl(ref t) => write!(f, "{:X?}", t),
            Ptr(p) => write!(f, "{:X?}", p),
        }
    }
}
