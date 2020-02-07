use crate::disasm::{
    instruction::Instruction,
    memmap::{CodeBlock, Section},
    pass1::FileBreak,
    mipsvals::MIPS3_INSN,
};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::ops::Range;

// move to csutils
static VALID_MIPS3_INSN: Lazy<HashSet<u32>> = Lazy::new(|| {
    MIPS3_INSN
        .iter()
        .map(|insn| *insn as u32)
        .collect()
});

#[derive(Debug)]
pub struct FindSectionState<'a> {
    vaddr: Option<NonZeroU32>,
    text_start: Option<NonZeroU32>,
    last_break: FileBreaks,
    transitions: Vec<Transition>,
    //sections: Vec<(Range<u32>, Section)>,
    block: &'a CodeBlock,
}

#[derive(Debug, Copy, Clone, Default)]
struct FileBreaks {
    possible_jrra_break: Option<NonZeroU32>,
    known_file_break: Option<NonZeroU32>,
}

impl FileBreaks {
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
enum Transition {
    DataToText(Range<u32>),
    TextToData(TextEndInfo),
}

#[derive(Debug)]
struct TextEndInfo {
    text: Range<u32>, data_end: u32, breaks: FileBreaks
}


impl<'a> FindSectionState<'a> {
    pub fn new(block: &'a CodeBlock) -> Self {
        Self {
            vaddr: None,
            text_start: None,
            last_break: FileBreaks::default(),
            transitions: Vec::with_capacity(4),
            block,
        }
    }

    pub fn check_insn(&mut self, insn: &Instruction) {
        use Transition::*;

        let vaddr = insn.vaddr;
        let nz_vaddr = NonZeroU32::new(vaddr)
            .expect("non-null instruction address");

        match self.vaddr {
            None => {
                let block_start = self.block.range.get_text_vaddr();

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
                let text_start = self.text_start
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
        if insn.jump.is_jrra() && (vaddr + 8) % 0x10 == 0  {
            self.last_break.new_jrra(nz_vaddr);
        } else if insn.file_break == FileBreak::Likely {
            self.last_break.new_file(nz_vaddr);
        }

        self.vaddr = Some(nz_vaddr);
    }

    /// Reify the set of `Transition`s into correctly sized `.text` and `.data` sections.
    /// The two big issues with using capstone's disassembled instructions is that 
    /// (1) capstone doesn't have a mips3 mode, so it will read data as illegal, later 
    ///     mips instructions, and
    /// (2) N64 RSP ucode is mostly valid (but nonsensical) mips3 code.
    /// This uses some basic heuristics to try to map file breaks between disassembled 
    /// "`.text` sections" "`.data` sections" to figure out the real file break between
    /// code and data
    pub fn finish(self, insns: &[Instruction]) -> Vec<(Range<u32>, Section)> {
        let final_pc = self.vaddr.expect("Non-null insn address").get() + 4;
        let block_start = self.block.range.get_text_vaddr(); // TODO: get_ram_start()
        let block_end = self.block.range.get_ram_end();
        let final_transition = self.final_transition(final_pc, block_end);

        // assert!(
        //     end <= block_end,
        //     "Block text ended outside of block RAM space"
        // );

        let calc_text_end = |info| find_real_text_end(insns, block_start, info);

        use Transition::*;
        let mut sections = Vec::with_capacity(self.transitions.len() + 1);
        for transition in self.transitions.into_iter().chain(final_transition) {
            match transition {
                DataToText(range) => sections.push((range, Section::Data)),
                TextToData(info) => {
                    let ranges = calc_text_end(info);
                    let iter = ranges.into_iter().cloned();

                    sections.extend(iter);
                }
            }
        }

        sections
    }

    fn end_text_block(&self, text: Range<u32>, data_end: u32) -> Transition {
        println!("Found the end of a .text section in block {}", &self.block.name);
        println!("{:2}{:x?}", "", self);

        Transition::TextToData(TextEndInfo{
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
        self.last_break = FileBreaks::reset(start);
    }

    fn final_transition(&self, end: u32, data_end: u32) -> Option<Transition> {
        let start = self.text_start.expect("Non-null start of .text").get();

        if start < end {
            Some(self.end_text_block(start..end, data_end))
        } else if end < data_end{
            Some(Transition::DataToText(end..data_end))
        } else {
            None
        }
    }
}

fn find_real_text_end(insns: &[Instruction], offset: u32, info: TextEndInfo) -> [(Range<u32>, Section); 2] {
    let mut end_counts = FindFileEnd::from(&info);
    println!("{:2}{:#x?}","", &info);

    if let Some(starting_vaddr) = end_counts.earliest_vaddr() {
        let starting_vaddr = dbg!(starting_vaddr.get());
        let first_insn_offset = dbg!((starting_vaddr - dbg!(offset)) as usize / 4);
        let relevant_insns = &insns[first_insn_offset..];

        end_counts.check_instructions(relevant_insns);

        println!("{:4}{:#x?}", "", &end_counts);
    }
    

    [
        (info.text.clone(), Section::Text),
        (info.text.end..info.data_end, Section::Data),
    ]
}

#[derive(Debug)]
struct FindFileEnd {
    jrra_file: Option<Malformed>,
    new_file: Option<Malformed>,
}

impl From<&TextEndInfo> for FindFileEnd {
    fn from(info: &TextEndInfo) -> Self {
        let jrra_file = info.breaks.possible_jrra_break.map(Malformed::new_at);
        let new_file = info.breaks.known_file_break.map(Malformed::new_at);

        Self {
            jrra_file, new_file
        }
    }
}

impl FindFileEnd {
    fn earliest_vaddr(&self) -> Option<NonZeroU32> {
        let mb_j = self.jrra_file.as_ref().map(|j| j.start_vaddr);
        let mb_n = self.new_file.as_ref().map(|n| n.start_vaddr);
        
        mb_j.and_then(|j| mb_n.map(|n| j.min(n)))
            .or(mb_j)
            .or(mb_n)
    }

    fn check_instructions(&mut self, insns: &[Instruction]) {
        if self.jrra_file.is_none() && self.new_file.is_none() {
            return;
        }

        for insn in insns {
            let issue = check_bad_insn(insn);
            let update_issue = |m| Malformed::update(m, insn.vaddr, issue);

            if let Some(bad) = issue {
                if bad == MalKinds::IllegalInsn {
                    println!("{:2} Found {:?} instruction", "", &bad);
                    println!("{:2} {:x?}", "", &insn);
                }
            }

            self.jrra_file.as_mut().map(update_issue);
            self.new_file.as_mut().map(update_issue);
        }
    }
}

#[derive(Debug)]
struct Malformed {
    start_vaddr: NonZeroU32,
    /// true if any instructions after `start_vaddr` are MIPSIV or later
    poisoned: bool,
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

        match kind {
            None => (),
            Some(Cop2) => self.cop2 = self.cop2.saturating_add(1),
            Some(Cop0) => self.cop0 = self.cop0.saturating_add(1),
            Some(IllegalInsn) => self.poisoned = true,
            Some(Jrra) => self.jrra = self.jrra.saturating_add(1),
            Some(SpUsage) => self.sp = self.sp.saturating_add(1),
            Some(OddRegUsage(n)) => self.odd_regs = self.odd_regs.saturating_add(n),
        };

        self
    }
}


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MalKinds {
    Cop2,
    Cop0,
    IllegalInsn,
    Jrra,
    SpUsage,
    OddRegUsage(u8),
}

fn check_bad_insn(insn: &Instruction) -> Option<MalKinds> {
    use MalKinds::*;
    use capstone::{RegId, arch::mips::MipsReg::*};

    const REG_SP: RegId = RegId(MIPS_REG_SP as u16);
    const OPCODE_MASK: u32  = 0b1111_1100_0000_0000_0000_0000_0000_0000;
    const COP0_OPS: u32     = 0b010_000;
    const COP2_OPS: u32     = 0b010_010;
    const COP1X_OPS: u32    = 0b010_011;
    const SPECIAL2_OPS: u32 = 0b011_100;
    const SPECIAL3_OPS: u32 = 0b011_111;

    let check_valid_insn = || bool_then(IllegalInsn, !VALID_MIPS3_INSN.contains(&(insn.id.0 as u32)));
    let check_sp_usage = || bool_then(SpUsage, insn.contains_reg(REG_SP));
    let check_jrra = || bool_then(Jrra, insn.jump.is_jrra());

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
}

fn bool_then<T>(t: T, b: bool) -> Option<T> {
    if b { Some(t) } else { None }
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
