use crate::disasm::{memmap::Section, pass1::BlockLoadedSections};
use err_derive::Error;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::fmt;
use std::ops::Range;

macro_rules! align {
    ($val: expr, $to: expr) => {
        (($val + ($to - 1)) & !($to - 1))
    };
}

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
type DataMap<'r> = BTreeMap<u32, DataEntry<'r>>;
type DataSizeMap = HashMap<u32, usize>;

// move to a parsedata module
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParsedData<'rom> {
    Float(u32),         // hex of float
    Double(u64),        // hex of double
    Asciz(&'rom str),   // str view of rom data; doesn't include \0
    JmpTbl(Box<[u32]>), // array of labels in current .text section
    Ptr(u32),           // standard pointer
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DataEntry<'rom> {
    pub addr: u32,
    pub data: ParsedData<'rom>,
}

#[derive(Debug)]
pub struct FindDataIter<'a, 'rom> {
    buffer: &'rom [u8],         // full data slice to parse
    start_ram: u32,             // start of full data slice
    csr: &'rom [u8],            // unparsed slice of buffer
    at: u32,                    // ram address of start of csr
    known: Option<DataSizeMap>, // map between known address and the size of known data
    vram: Range<u32>,
    sections: &'a BlockLoadedSections,
    yielded: Option<DpResult<DataEntry<'rom>>>,
    state: State,
}

impl<'a, 'rom> Iterator for FindDataIter<'a, 'rom> {
    type Item = DpResult<DataEntry<'rom>>;

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
    Failure(String),
    Finished,
}

#[derive(Debug, Copy, Clone)]
enum Event {
    NothingFound,
    IssueReported,
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
            (Checking, NothingFound) => Checking,
            // Buffered data to process
            (_, BufferedPtr(offset, ptr)) => AddPtr(offset, ptr),
            (_, BufferedAscii(offset)) => ParseAscii(offset),
            // Single pointer to outside of this sections .text
            (Checking, FoundPtr(offset, ptr)) => AddPtr(offset, ptr),
            // Single pointer to this sections .text
            (Checking, FoundTextPtr(offset, ptr)) => StartJmpTbl(offset, ptr),
            (StartJmpTbl(offset, ptr), NothingFound) => AddPtr(*offset, *ptr),
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
            (GrowJmpTbl(offset, ref mut tbl), NothingFound) => EndJmpTbl(*offset, tbl.take()),
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
            (_, NothingFound) => Checking,

            // Error
            (Failure(..), IssueReported) => Finished,
            (s, e) => Failure(format!("{:x?} with {:x?}", s, e)),
        }
    }
}

impl<'a, 'rom> FindDataIter<'a, 'rom> {
    pub fn new(
        buffer: &'rom [u8],
        start_ram: u32,
        sections: &'a BlockLoadedSections,
        use_mempak: bool,
        known: Option<&DataMap<'_>>,
    ) -> DpResult<Self> {
        if buffer.len() % 4 != 0 {
            return Err(DataParseErr::BadDataLen);
        }
        if start_ram % 4 != 0 {
            return Err(DataParseErr::BadDataAlign);
        }

        let vram = if use_mempak {
            0x8000_0400..0x8080_0000
        } else {
            0x8000_0400..0x8040_0000
        };

        let known = known.map(|m| {
            m.iter()
                .map(|(addr, entry)| (*addr, entry.byte_size()))
                .collect()
        });

        Ok(Self {
            buffer,
            start_ram,
            csr: buffer,
            at: start_ram,
            known,
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
                self.yielded = Some(Ok(entry));

                YieldData
            }
            AddTwoPtr(ptrs) => {
                let [p1, p2] = ptrs;
                let entry1 = DataEntry::tupple_ptr(p1);
                self.yielded = Some(Ok(entry1));

                BufferedPtr(p2.0, p2.1)
            }
            StartJmpTbl(..) => self.check_next_word(),
            GrowJmpTbl(..) => self.check_next_word(),
            EndJmpTbl(addr, ref mut tbl) => {
                let tbl = tbl.take().unwrap();
                let tbl = DataEntry::jmp_tbl(addr, tbl);
                self.yielded = Some(Ok(tbl));

                YieldData
            }
            EndJmpTblAndPtr((offset, ref mut tbl), (off2, ptr2)) => {
                let tbl = tbl.take().unwrap();
                let tbl = DataEntry::jmp_tbl(offset, tbl);
                self.yielded = Some(Ok(tbl));

                BufferedPtr(off2, ptr2)
            }

            EndJmpTblAndAscii((offset, ref mut tbl), ascii_off) => {
                let tbl = tbl.take().unwrap();
                let tbl = DataEntry::jmp_tbl(offset, tbl);
                self.yielded = Some(Ok(tbl));

                BufferedAscii(ascii_off)
            }

            PtrThenAscii(ptr, ascii_off) => {
                let entry = DataEntry::tupple_ptr(ptr);
                self.yielded = Some(Ok(entry));

                BufferedAscii(ascii_off)
            }

            ParseAscii(offset) => self.parse_ascii(offset),

            Failure(ref s) => {
                let problem = DataParseErr::SmFail(self.at, s.clone());
                self.yielded = Some(Err(problem));

                IssueReported
            }
            Finished => NothingFound,
        }
    }

    fn parse_ascii(&mut self, start_offset: u32) -> Event {
        const NUL: u8 = b'\0';

        let str_buffer = self.offset_to_slice(start_offset);
        let size = str_buffer
            .iter()
            .copied()
            .take_while(|&b| useful_ascii(b))
            .count();

        if size == 0 {
            return Event::NothingFound;
        }
        // check that the final byte was the nul terminator
        match str_buffer.get(size).copied() {
            Some(b) if b == NUL => (),
            None => return Event::NothingFound,
            Some(_) => return Event::NothingFound,
        };
        // check that all bytes up to the next word alignment are NUL
        // as IDO aligns string rodata to the nearest word with pad NUL bytes
        let is_aligned_null = str_buffer
            .get(size..align!(size + 1, 4))
            .map_or(true, |s| s.iter().all(|b| *b == NUL));
        if !is_aligned_null {
            return Event::NothingFound;
        }

        let possible_str = &str_buffer[..size];
        let ascii_str = std::str::from_utf8(possible_str).expect("valid ascii str");

        let str_end_ram = start_offset + (size as u32) + 1;
        let entry = DataEntry::asciiz(start_offset, ascii_str);

        self.yielded = Some(Ok(entry));

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
    /// check if there is already parsed data at RAM `addr`.
    /// If so, return the size of the known `DataEntry`
    fn check_if_known(&self, addr: u32) -> Option<usize> {
        self.known.as_ref().and_then(|m| m.get(&addr)).copied()
    }
    /// Advance the internal cursor to the address `to` aligned to
    /// 4 bytes. Returns false if the cursor could not be advanced (EOF)
    fn advance_and_word_align(&mut self, to: u32) -> bool {
        let csr_ram_addr = self.at;
        let to_aligned = align!(to, 4);
        let new_csr_start = (to_aligned - csr_ram_addr) as usize;

        if new_csr_start < self.csr.len() {
            self.csr = &self.csr[new_csr_start..];
            self.at = to_aligned;

            true
        } else {
            false
        }
    }
    fn advance_by_aligned(&mut self, by: u32) -> bool {
        self.advance_and_word_align(self.at + by)
    }

    fn check_next_word(&mut self) -> Event {
        use Event::*;

        if self.csr.len() < 4 {
            return EndOfData;
        }

        if let Some(size) = self.check_if_known(self.at) {
            if !self.advance_by_aligned(size as u32) {
                return EndOfData;
            } else {
                return NothingFound;
            }
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
            NothingFound
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
    pub fn ptr(addr: u32, ptr: u32) -> Self {
        Self {
            addr,
            data: ParsedData::Ptr(ptr),
        }
    }
    fn tupple_ptr(set: (u32, u32)) -> Self {
        Self {
            addr: set.0,
            data: ParsedData::Ptr(set.1),
        }
    }
    fn asciiz(addr: u32, ptr: &'rom str) -> Self {
        Self {
            addr,
            data: ParsedData::Asciz(ptr),
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
    pub fn byte_size(&self) -> usize {
        use ParsedData::*;

        match self.data {
            Float(..) => 4,
            Double(..) => 8,
            Asciz(ref s) => align!(s.len() + 1, 4), // include NUL byte
            JmpTbl(ref t) => t.len() * 4,
            Ptr(..) => 4,
        }
    }
}

impl<'rom> fmt::Display for DataEntry<'rom> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsedData::*;

        match self.data {
            Float(h) => {
                let mut buf = ryu::Buffer::new();
                let pretty = buf.format(f32::from_bits(h));
                write!(f, "{}", pretty)
            }
            Double(h) => {
                let mut buf = ryu::Buffer::new();
                let pretty = buf.format(f64::from_bits(h));
                write!(f, "{}", pretty)
            }
            Asciz(s) => write!(f, "{:?}", s),
            JmpTbl(ref t) => write!(f, "{:X?}", t),
            Ptr(p) => write!(f, "{:X?}", p),
        }
    }
}

// check if byte is ascii alphanumeric, symbol, or ' ', \n, \r, \t
fn useful_ascii(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || (b.is_ascii_whitespace() && b != 0x0C)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_useful_ascii() {
        let valid = [
            b'a', b'Z', b'0', b'!', b'\n', b' ', b'9', b'%', b'\'', b'\\', b'~',
        ];
        let invalid = [
            b'\0', 0x14, 0x01, 0x02, 0x03, 0x4, 0x5, 0x6, 0x7, 0x18, 0x7F,
        ];
        let valid_ws = [b' ', b'\n', b'\r', b'\n'];
        let invalid_ws = [0x0C];

        assert!(
            valid.iter().copied().all(useful_ascii),
            "valid ascii read as invalid"
        );
        assert!(
            invalid.iter().copied().all(|b| !useful_ascii(b)),
            "invalid ascii read as valid"
        );
        assert!(
            valid_ws.iter().copied().all(useful_ascii),
            "valid ascii whitespace read as invalid"
        );
        assert!(
            invalid_ws.iter().copied().all(|b| !useful_ascii(b)),
            "invalid ascii whitespace read as valid"
        );
    }

    #[test]
    fn check_align() {
        assert_eq!(align!(0x11, 4), 0x14);
        assert_eq!(align!(0x11, 8), 0x18);
        assert_eq!(align!(0x11, 16), 0x20);
    }
}
