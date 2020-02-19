use crate::boolext::BoolOptionExt;
use crate::disasm::{
    csutil::VALID_MIPS3_INSNS,
    instruction::Instruction,
    memmap::{CodeBlock, Section},
    pass1::FileBreak,
};
use log::debug;
use std::cmp::Ordering;
use std::num::NonZeroU32;
use std::ops::Range;

///! Deal with capstone's overeager disassembly of .data section into .text instructions,
///! and capstone problems with disassembling mips code.
///! For incorrect disassembly of data, there are a few obvious tells:
///! (1) The common N64 toolchain (ido/mipspro/makerom) will pad object sections to the
///!     nearest 16-byte boundry (0x10 aligned). If the final instruction capstone found
///!     does not end at 0x..C so that the next valid address is 0x..10, then there is an issue.
///! (2) Instructions in a new section (obj1.text then obj2.text) that don't include a `jr $ra`
///!     Divergent functions that end files should be so incredibly rare that if a section
///!     does not have a `jr $ra` then assume it's a bad disassembly.
///! The two big issues with using capstone's disassembled instructions is that
///! (1) capstone doesn't have a mips3 mode, so it will read data as illegal, later
///!     mips instructions, and
///! (2) N64 RSP ucode is mostly valid (but nonsensical) mips3 code. Luckily, the `$k0`
///!     and `$k1` registers are very important in Nintendo's ucode, so any appearances
///!     of those registers indicates an improperly decoded instruction.

#[derive(Debug)]
pub struct BlockLoadedSections(Box<[LoadSectionInfo]>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoadSectionInfo {
    pub kind: Section,
    pub range: Range<u32>,
}

#[derive(Debug)]
pub struct FindSectionState<'a> {
    vaddr: Option<NonZeroU32>,
    text_start: Option<NonZeroU32>,
    last_break: Breaks,
    transitions: Vec<Transition>,
    block: &'a CodeBlock,
}

#[derive(Debug, Copy, Clone, Default)]
struct Breaks {
    possible_jrra_break: Option<NonZeroU32>,
    known_file_break: Option<NonZeroU32>,
}

#[derive(Debug)]
enum Transition {
    DataToText(Range<u32>),
    TextToData(TextEndInfo),
}

#[derive(Debug)]
struct TextEndInfo {
    text: Range<u32>,
    data_end: u32,
    breaks: Breaks,
}

impl BlockLoadedSections {
    pub fn find_address(&self, addr: u32) -> Option<&LoadSectionInfo> {
        self.0
            .binary_search_by(|probe| probe.find_addr(addr))
            .ok()
            .map(|i| &self.0[i])
    }
    /// Create a tupple of new `BlockLoadedSections`, one for .text and the other for .data.
    /// (.text, .data)
    pub fn clone_into_separate(&self) -> (Self, Self) {
        let (text, data): (Vec<_>, Vec<_>) = self
            .0
            .iter()
            .cloned()
            .partition(|s| s.kind == Section::Text);
        (text.into(), data.into())
    }

    pub fn as_slice(&self) -> &[LoadSectionInfo] {
        &self.0
    }
}

impl From<Vec<LoadSectionInfo>> for BlockLoadedSections {
    fn from(vec: Vec<LoadSectionInfo>) -> Self {
        Self(vec.into_boxed_slice())
    }
}

impl LoadSectionInfo {
    fn find_addr(&self, addr: u32) -> Ordering {
        if self.range.contains(&addr) {
            Ordering::Equal
        } else if self.range.start > addr {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    fn data(range: Range<u32>) -> Self {
        Self {
            kind: Section::Data,
            range,
        }
    }
    fn text(range: Range<u32>) -> Self {
        Self {
            kind: Section::Text,
            range,
        }
    }
}

impl<'a> FindSectionState<'a> {
    pub fn new(block: &'a CodeBlock) -> Self {
        Self {
            vaddr: None,
            text_start: None,
            last_break: Breaks::default(),
            transitions: Vec::with_capacity(4),
            block,
        }
    }

    pub fn check_insn(&mut self, insn: &Instruction) {
        use Transition::*;

        let vaddr = insn.vaddr;
        let nz_vaddr = NonZeroU32::new(vaddr).expect("non-null instruction address");

        match self.vaddr {
            None => {
                let block_start = self.block.range.get_ram_start();

                assert!(
                    block_start <= vaddr,
                    "Start of a code block after the address of the first instruction"
                );
                if block_start < vaddr {
                    self.transitions.push(DataToText(block_start..vaddr));
                }

                self.reset(vaddr);
            }
            Some(prior) if prior.get() + 4 != vaddr => {
                // there was a hole in machine code (.text -> .data -> .text)
                let text_start = self
                    .text_start
                    .expect(".text block must start before a hole in instruction addresses")
                    .get();
                let prior_end = prior.get() + 4;
                let t2d_transition = self.end_text_block(text_start..prior_end, vaddr);

                self.transitions.push(t2d_transition);
                self.reset(vaddr);
            }
            Some(..) => (),
        }

        // if there's a possible jrra that ends a file (pc after delay is 16byte-aligned)
        // reset the counting state for hidden file breaks.
        if insn.jump.is_jrra() && (vaddr + 8) % 0x10 == 0 {
            self.last_break.new_jrra(nz_vaddr);
        } else if insn.file_break == FileBreak::Likely {
            self.last_break.new_file(nz_vaddr);
        }

        self.vaddr = Some(nz_vaddr);
    }

    /// Reify all of the `Transition`s into a sorted `BlockLoadedSections` that has
    /// the proper sizes for each of the `.text` and `.data` sections. The returning
    /// `BlockLoadedSections` is sorted by the memory range each section takes.
    /// # Panic
    /// Panics if there are any overlaping sections
    pub fn finish(self, insns: &[Instruction]) -> BlockLoadedSections {
        use Transition::*;

        let final_pc = self.vaddr.expect("Non-null insn address").get() + 4;
        let block_start = self.block.range.get_ram_start(); // TODO: get_ram_start()
        let block_end = self.block.range.get_ram_end();
        let final_transition = self.final_transition(final_pc, block_end);

        let iter_text_end = |info| get_text_data_sections(insns, block_start, final_pc, info);

        let mut sections = Vec::with_capacity(self.transitions.len().max(1) * 2);
        for transition in self.transitions.into_iter().chain(final_transition) {
            match transition {
                DataToText(range) => sections.push(LoadSectionInfo::data(range)),
                TextToData(info) => {
                    sections.extend(iter_text_end(info));
                }
            }
        }

        sections.sort_unstable_by(|a, b| {
            let ar = &a.range;
            let br = &b.range;

            if ar.start < br.start && ar.end <= br.start {
                Ordering::Less
            } else if br.start < ar.start && br.end <= ar.start {
                Ordering::Greater
            } else {
                panic!("Overlapping sections on sort:\n{:#x?}\n{:#x?}", a, b);
            }
        });

        sections.into()
    }

    fn end_text_block(&self, text: Range<u32>, data_end: u32) -> Transition {
        println!("Ending a .text section in block {}", &self.block.name);

        Transition::TextToData(TextEndInfo {
            text,
            data_end,
            breaks: self.last_break,
        })
    }

    /// Reset state to record the start of a new .text section,
    /// and reset the file break locations
    fn reset(&mut self, new_start: u32) {
        let start = NonZeroU32::new(new_start);

        self.text_start = start;
        self.last_break = Breaks::reset(start);
    }

    fn final_transition(&self, text_end: u32, block_end: u32) -> Option<Transition> {
        let start = self.text_start.expect("Non-null start of .text").get();

        if start < text_end {
            Some(self.end_text_block(start..text_end, block_end))
        } else if text_end < block_end {
            // so, the .text start is equal to text end, but there's still
            // space, that space must be Data
            Some(Transition::DataToText(text_end..block_end))
        } else {
            None
        }
    }
}

fn get_text_data_sections(
    insns: &[Instruction],
    offset: u32,
    text_end: u32,
    info: TextEndInfo,
) -> impl Iterator<Item = LoadSectionInfo> {
    use std::iter::once;

    let mut find_end = FindFileEnd::from((&info, text_end));

    if let Some(starting_vaddr) = find_end.earliest_vaddr() {
        let starting_vaddr = starting_vaddr.get();
        let first_insn_offset = (starting_vaddr - offset) as usize / 4;
        let relevant_insns = &insns[first_insn_offset..];

        find_end.check_instructions(relevant_insns);

        debug!("{:4}{:#x?}", "", &find_end);
    }

    let start = info.text.start;
    let old_end = info.text.end;
    let data_end = info.data_end;
    let new_end = find_end.find_text_boundry();
    println!(
        "Old .text end {:x} == New .text end {:x}? {}",
        old_end,
        new_end,
        old_end == new_end
    );

    let text = LoadSectionInfo::text(start..new_end);
    let data = LoadSectionInfo::data(new_end..data_end);

    once(text).chain(once(data))
}

impl Breaks {
    // all transitions between .text and .data sections are file breaks
    // due to the behavior of the typical n64 linker (if not all linkers)
    fn reset(new_start: Option<NonZeroU32>) -> Self {
        Self {
            possible_jrra_break: None,
            known_file_break: new_start,
        }
    }
    // store the location after the jrra and the delay slot
    fn new_jrra(&mut self, addr: NonZeroU32) {
        let pc_after_jump = NonZeroU32::new(addr.get() + 8);
        self.possible_jrra_break = pc_after_jump;
    }

    fn new_file(&mut self, addr: NonZeroU32) {
        self.known_file_break = Some(addr);
    }
}

#[derive(Debug)]
struct FindFileEnd {
    jrra_file: Option<Malformed>,
    new_file: Option<Malformed>,
    text_end: u32,
    ram_map: Vec<(Range<u32>, FileBreakKind)>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum FileBreakKind {
    AfterJrra,
    KnownBreak,
}

impl From<(&TextEndInfo, u32)> for FindFileEnd {
    fn from((info, text_end): (&TextEndInfo, u32)) -> Self {
        use FileBreakKind::*;

        let jrra_file = info.breaks.possible_jrra_break.map(Malformed::new_at);
        let new_file = info.breaks.known_file_break.map(Malformed::new_at);

        let start = |m: &Malformed| m.start_vaddr.get();

        let ram_map = match (jrra_file.as_ref(), new_file.as_ref()) {
            (Some(j), Some(f)) => {
                let j = start(j);
                let f = start(f);

                let lower = j.min(f);
                if lower == j {
                    vec![(j..f, AfterJrra), (f..text_end, KnownBreak)]
                } else {
                    vec![(f..j, KnownBreak), (j..text_end, AfterJrra)]
                }
            }
            (Some(j), None) => vec![((start(j)..text_end, AfterJrra))],
            (None, Some(f)) => vec![((start(f)..text_end, KnownBreak))],
            (None, None) => vec![],
        };

        Self {
            jrra_file,
            new_file,
            text_end,
            ram_map,
        }
    }
}

impl FindFileEnd {
    fn earliest_vaddr(&self) -> Option<NonZeroU32> {
        let mb_j = self.jrra_file.as_ref().map(|j| j.start_vaddr);
        let mb_n = self.new_file.as_ref().map(|n| n.start_vaddr);

        mb_j.and_then(|j| mb_n.map(|n| j.min(n))).or(mb_j).or(mb_n)
    }

    fn latest_vaddr(&self) -> Option<NonZeroU32> {
        let mb_j = self.jrra_file.as_ref().map(|j| j.start_vaddr);
        let mb_n = self.new_file.as_ref().map(|n| n.start_vaddr);

        mb_j.and_then(|j| mb_n.map(|n| j.max(n))).or(mb_j).or(mb_n)
    }

    fn check_instructions<'a>(&mut self, insns: &'a [Instruction]) {
        use FileBreakKind::*;

        if self.jrra_file.is_none() && self.new_file.is_none() {
            return;
        }

        let ram_map = &self.ram_map;
        let find_addr = |a| ram_map.iter().find_map(|r| r.0.contains(&a).b_then(r.1));
        let map_insn_to_area = |i: &'a Instruction| find_addr(i.vaddr).map(|l| (i, l));
        let insns_iter = insns.into_iter().filter_map(map_insn_to_area);

        for (insn, location) in insns_iter {
            let issue = check_bad_insn(insn);
            let update_issue = |m| Malformed::update(m, insn.vaddr, issue);

            if let Some(bad) = issue {
                if bad == MalKinds::IllegalInsn {
                    debug!("{:2} Found {:?} instruction", "", &bad);
                    debug!("{:2} {:x?}", "", &insn);
                }
            }

            match location {
                AfterJrra => self.jrra_file.as_mut().map(update_issue),
                KnownBreak => self.new_file.as_mut().map(update_issue),
            };
        }
    }

    /// Find the "real boundry" between a .text and .data section based
    /// on the gathered info in the `Malformed` structures
    fn find_text_boundry(&self) -> u32 {
        let align16_end = || self.text_end & !0xF;
        let check_capstone_end = || {
            if self.text_end % 0x10 != 0 {
                self.latest_vaddr()
                    .map_or_else(align16_end, NonZeroU32::get)
            } else {
                self.text_end
            }
        };

        // If the `Malformed` reports a higher value than CUTOFF,
        // anything after that file break is illegal. So, the end of the .text
        // section has to be at the start of the `Malformed`.
        // Otherwise if no issues were found, use the end address that capstone
        // determined, unless that ending is obviously bad (not 16-byte aligned)
        self.ram_map
            .iter()
            .filter_map(|(_, k)| self.get(*k))
            .find(|mal| mal.is_bad_block())
            .map(|mal| mal.start_vaddr.get())
            .unwrap_or_else(check_capstone_end)
    }

    fn get(&self, kind: FileBreakKind) -> Option<&Malformed> {
        use FileBreakKind::*;
        match kind {
            AfterJrra => self.jrra_file.as_ref(),
            KnownBreak => self.new_file.as_ref(),
        }
    }
}

/// This keeps track of odd and/or illegal problems that occur between
/// `start_vaddr` and `start_vaddr + 4 * count`.
#[derive(Debug)]
struct Malformed {
    start_vaddr: NonZeroU32,
    /// true if any instructions after `start_vaddr` are MIPSIV or later
    poisoned: bool,
    count: u32,
    cop2: u8,
    cop0: u8,
    jrra: u8,
    sp: u8,
    odd_regs: u8,
}

impl Malformed {
    fn new_at(start_vaddr: NonZeroU32) -> Self {
        Self {
            start_vaddr,
            poisoned: false,
            count: 0,
            cop2: 0,
            cop0: 0,
            jrra: 0,
            sp: 0,
            odd_regs: 0,
        }
    }

    fn update(&mut self, at: u32, kind: Option<MalKinds>) -> &mut Self {
        use MalKinds::*;

        if at < self.start_vaddr.get() {
            return self;
        }

        self.count += 1;

        match kind {
            None => (),
            Some(Cop2) => self.cop2 = self.cop2.saturating_add(1),
            Some(Cop0) => self.cop0 = self.cop0.saturating_add(1),
            Some(IllegalInsn) => self.poisoned = true,
            Some(Jrra) => self.jrra = self.jrra.saturating_add(1),
            Some(SpUsage) => self.sp = self.sp.saturating_add(1),
            Some(IllegalRegUsage) => self.odd_regs = self.odd_regs.saturating_add(1),
        };

        self
    }

    /// Are the instructions after `self.text_start` legal or illegal?
    fn is_bad_block(&self) -> bool {
        const CUTOFF: u8 = 240;

        (if self.poisoned {
            // mips4+ instruction
            255
        } else if self.cop2 > 0 {
            // RSP microcode
            255
        } else if self.odd_regs > 0 {
            // k0, k1, or gp usasge
            255
        } else if self.jrra == 0 {
            // divergent functions that end files shouldn't happen
            // so this block is probably data being interepted as code
            255
        } else {
            0
        }) > CUTOFF
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MalKinds {
    Cop2,
    Cop0,
    IllegalInsn,
    Jrra,
    SpUsage,
    IllegalRegUsage,
}

fn check_bad_insn(insn: &Instruction) -> Option<MalKinds> {
    use capstone::{arch::mips::MipsReg::*, RegId};
    use MalKinds::*;

    const OPCODE_MASK: u32 = 0b1111_1100_0000_0000_0000_0000_0000_0000;
    const COP0_OPS: u32 = 0b010_000;
    const COP2_OPS: u32 = 0b010_010;
    const COP1X_OPS: u32 = 0b010_011;
    const SPECIAL2_OPS: u32 = 0b011_100;
    const SPECIAL3_OPS: u32 = 0b011_111;

    const REG_SP: RegId = RegId(MIPS_REG_SP as u16);
    const REG_K0: RegId = RegId(MIPS_REG_K0 as u16);
    const REG_K1: RegId = RegId(MIPS_REG_K1 as u16);
    const REG_GP: RegId = RegId(MIPS_REG_GP as u16);
    const ILLEGAL_OPS: [RegId; 3] = [REG_K0, REG_K1, REG_GP];
    let contains_illegal = || {
        ILLEGAL_OPS
            .iter()
            .copied()
            .any(|reg| insn.contains_reg(reg))
    };

    let insn_id = insn.id.0 as u32;
    let check_valid_insn = || (!VALID_MIPS3_INSNS.contains(&insn_id)).b_then(IllegalInsn);
    let check_sp_usage = || insn.contains_reg(REG_SP).b_then(SpUsage);
    let check_jrra = || insn.jump.is_jrra().b_then(Jrra);
    let check_illegal_regs = || contains_illegal().b_then(IllegalRegUsage);

    let op = (insn.raw & OPCODE_MASK) >> 26;

    match op {
        COP0_OPS => Some(Cop0),
        COP2_OPS => Some(Cop2),
        COP1X_OPS | SPECIAL2_OPS | SPECIAL3_OPS => Some(IllegalInsn),
        _ => None,
    }
    .or_else(check_valid_insn)
    .or_else(check_sp_usage)
    .or_else(check_jrra)
    .or_else(check_illegal_regs)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::disasm::csutil;
    use MalKinds::*;

    const COP0_OPS: [u8; 2 * 4] = [0x40, 0x81, 0x00, 0x00, 0x40, 0x04, 0x28, 0x00];

    const COP2_OPS: [u8; 2 * 4] = [0x48, 0x1E, 0x28, 0x00, 0x48, 0x80, 0x38, 0x00];

    const COP3_OPS: [u8; 2 * 4] = [0x4C, 0x80, 0x38, 0x00, 0x4C, 0x1E, 0x28, 0x00];

    fn raw_to_instruction(raw: &[u8]) -> Vec<Instruction> {
        let cs = csutil::get_instance().expect("working Capstone lib");

        let output = cs
            .disasm_all(raw, 0x80004000)
            .expect("valid instructions")
            .iter()
            .map(|i| {
                let detail = cs.insn_detail(&i).expect("capstone detailed mode");
                Instruction::from_components(&i, &detail)
                    .expect("valid conversion from capstone instruction to custom instruction")
            })
            .collect();

        output
    }

    #[test]
    fn test_coprocessor_masks() {
        fn check_mal_kind(o: Option<MalKinds>, kind: MalKinds) -> bool {
            o.map_or(false, |k| k == kind)
        }
        let is_cop0 = |o| check_mal_kind(o, Cop0);
        let is_cop2 = |o| check_mal_kind(o, Cop2);
        let is_cop3 = |o| check_mal_kind(o, IllegalInsn);

        let cop0 = raw_to_instruction(&COP0_OPS)
            .iter()
            .map(check_bad_insn)
            .all(is_cop0);

        assert!(
            cop0,
            "COP0 instruction mask didn't catch all cop0 instructions"
        );

        let cop2 = raw_to_instruction(&COP2_OPS)
            .iter()
            .map(check_bad_insn)
            .all(is_cop2);

        assert!(
            cop2,
            "COP0 instruction mask didn't catch all cop0 instructions"
        );

        let cop3 = raw_to_instruction(&COP3_OPS)
            .iter()
            .map(check_bad_insn)
            .all(is_cop3);

        assert!(
            cop3,
            "COP0 instruction mask didn't catch all cop0 instructions"
        );
    }
}
