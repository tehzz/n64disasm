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
    last_file_jrra: Option<Malformed>,
    last_file_break: Option<Malformed>,
    sections: Vec<(Range<u32>, Section)>,
    block: &'a CodeBlock,
}

#[derive(Debug)]
struct Malformed {
    start_vaddr: u32,
    /// true if any instructions after `start_vaddr` are MIPSIV or later
    poisoned: bool,
    cop2: u8,
    cop0: u8,
    jrras: u8,
    sp: u8,
    odd_regs: u8,
}

impl Malformed {
    fn new_at(start_vaddr: u32) -> Self {
        Self {
            start_vaddr,
            poisoned: false,
            cop2: 0,
            cop0: 0,
            jrras: 0,
            sp: 0,
            odd_regs: 0,
        }
    }

    fn update(&mut self, kind: Option<MalKinds>) -> &mut Self {
        use MalKinds::*;

        match kind {
            None => (),
            Some(Cop2) => self.cop2 = self.cop2.saturating_add(1),
            Some(Cop0) => self.cop0 = self.cop0.saturating_add(1),
            Some(IllegalInsn) => self.poisoned = true,
            Some(SpUsage) => self.sp = self.sp.saturating_add(1),
            Some(OddRegUsage(n)) => self.odd_regs = self.odd_regs.saturating_add(n),
        };

        self
    }

    fn add_jrra(&mut self) {
        self.jrras = self.jrras.saturating_add(1);
    }
}


impl<'a> FindSectionState<'a> {
    pub fn new(block: &'a CodeBlock) -> Self {
        Self {
            vaddr: None,
            text_start: None,
            last_file_jrra: None,
            last_file_break: None,
            sections: Vec::with_capacity(4),
            block,
        }
    }

    pub fn finish(mut self) -> Vec<(Range<u32>, Section)> {
        let final_pc = self.vaddr.unwrap().get() + 4;
        let (start, end) = self.end_text_block(final_pc);
        let block_end = self.block.range.get_ram_end();

        assert!(
            end <= block_end,
            "Block text ended outside of block RAM space"
        );

        self.sections.push((start..end, Section::Text));

        if end < block_end {
            self.sections.push((end..block_end, Section::Data));
        }

        self.sections
    }

    pub fn check_insn(&mut self, insn: &Instruction) {
        let vaddr = insn.vaddr;

        match self.vaddr {
            None => {
                let start = self.block.range.get_text_vaddr();

                assert!(
                    start <= vaddr,
                    "Start of a code block after the address of the first instruction"
                );
                if start < vaddr {
                    self.sections.push((start..vaddr, Section::Data));
                }

                self.reset(vaddr);
            }
            Some(prior) if prior.get() + 4 != vaddr => {
                // there was a hole in machine code (.text -> .data -> .text)
                let next = prior.get() + 4;
                let (text_start, text_end) = self.end_text_block(next);

                self.sections.push((text_start..text_end, Section::Text));
                self.sections.push((text_end..vaddr, Section::Data));
                self.reset(vaddr);
            }
            Some(..) => (),
        }

        // if there's a possible jrra that ends a file (pc after delay is 16byte-aligned)
        // reset the counting state for hidden file breaks. Else, count the jrra
        if insn.jump.is_jrra() {
            if (vaddr + 8) % 0x10 == 0 {
                self.last_file_jrra = Some(Malformed::new_at(vaddr));
            } else {
                self.last_file_jrra.as_mut().map(Malformed::add_jrra);
                self.last_file_break.as_mut().map(Malformed::add_jrra);
            }
        }

        if insn.file_break == FileBreak::Likely {
            self.last_file_break = Some(Malformed::new_at(vaddr));
        }

        let possible_issues = check_bad_insn(&insn);
        let update_issue = |m| Malformed::update(m, possible_issues);

        if let Some(bad) = possible_issues {
            if bad == MalKinds::IllegalInsn {
                println!("{:2} Found {:?} instruction", "", &bad);
                println!("{:2} {:x?}", "", &insn);
            }
        }

        self.last_file_jrra.as_mut().map(update_issue);
        self.last_file_break.as_mut().map(update_issue);
        // TODO: make an error type here and use try_from
        self.vaddr = NonZeroU32::new(vaddr);
    }

    fn end_text_block(&self, end: u32) -> (u32, u32) {
        println!("Tried to end .text section in block {}", &self.block.name);
        println!("{:2}{:#x?}", "", self);
        // todo: poison checks to find possible ends
        (self.text_start.unwrap().get(), end)
    }

    /// Reset the start of this .text section, and reset the
    /// various bad disassembly structs
    fn reset(&mut self, new_start: u32) {
        // TODO: make an error type here and use try_from
        self.text_start = NonZeroU32::new(new_start);
        self.last_file_jrra = None;
        self.last_file_break = Some(Malformed::new_at(new_start));
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MalKinds {
    Cop2,
    Cop0,
    IllegalInsn,
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

    let op = (insn.raw & OPCODE_MASK) >> 26;

    match op {
        COP0_OPS => Some(Cop0),
        COP2_OPS => Some(Cop2),
        COP1X_OPS | SPECIAL2_OPS | SPECIAL3_OPS => Some(IllegalInsn),
        _ => None,
    }
    .or_else(check_valid_insn)
    .or_else(check_sp_usage)
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
