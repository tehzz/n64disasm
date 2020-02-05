use crate::disasm::{
    instruction::Instruction,
    memmap::{CodeBlock, Section},
    pass1::FileBreak,
};
use std::num::NonZeroU32;
use std::ops::Range;

#[derive(Debug)]
pub struct FindSectionState<'a> {
    vaddr: Option<NonZeroU32>,
    text_start: Option<NonZeroU32>,
    last_jrra: Option<Malformed>,
    last_file_break: Option<Malformed>,
    sections: Vec<(Range<u32>, Section)>,
    block: &'a CodeBlock,
}

#[derive(Debug)]
struct Malformed {
    start_vaddr: u32,
    /// true if any instructions after `start_vaddr` are MIPSIV or later
    poisoned: bool,
    cop2: u16,
    cop0: u16,
    sp: u16,
}

impl Malformed {
    fn new_at(start_vaddr: u32) -> Self {
        Self {
            start_vaddr,
            poisoned: false,
            cop2: 0,
            cop0: 0,
            sp: 0,
        }
    }

    fn update(&mut self, kind: Option<MalKinds>) -> &mut Self {
        use MalKinds::*;
        match kind {
            None => (),
            Some(Cop2) => self.cop2 += 1,
            Some(Cop0) => self.cop0 += 1,
            Some(SpUsage) => self.sp += 1,
            Some(IllegalInsn) => self.poisoned = true,
        };

        self
    }
}

impl<'a> FindSectionState<'a> {
    pub fn new(block: &'a CodeBlock) -> Self {
        Self {
            vaddr: None,
            text_start: None,
            last_jrra: None,
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

        if insn.jump.is_jrra() {
            self.last_jrra = Some(Malformed::new_at(vaddr));
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

        self.last_jrra.as_mut().map(update_issue);
        self.last_file_break.as_mut().map(update_issue);
        // TODO: make an error type here and use try_from
        self.vaddr = NonZeroU32::new(vaddr);
    }

    fn end_text_block(&self, end: u32) -> (u32, u32) {
        println!("Tried to end .text section in block {}", &self.block.name);
        println!("{:2}{:x?}", "", self);
        // todo: poison checks to find possible ends
        (self.text_start.unwrap().get(), end)
    }

    /// Reset the start of this .text section, and reset the
    /// various bad disassembly structs
    fn reset(&mut self, new_start: u32) {
        // TODO: make an error type here and use try_from
        self.text_start = NonZeroU32::new(new_start);
        self.last_jrra = None;
        self.last_file_break = Some(Malformed::new_at(new_start));
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MalKinds {
    Cop2,
    Cop0,
    IllegalInsn,
    SpUsage,
}

fn check_bad_insn(insn: &Instruction) -> Option<MalKinds> {
    use MalKinds::*;

    const OPCODE_MASK: u32 = 0b1111_1100_0000_0000_0000_0000_0000_0000;
    const COP0_OPS: u32 = 0b010_000;
    const COP2_OPS: u32 = 0b010_010;
    const COP1X_OPS: u32 = 0b010_011;
    const SPECIAL2_OPS: u32 = 0b011_100;
    const SPECIAL3_OPS: u32 = 0b011_111;

    let check_valid_insn = || {
        if VALID_MIPS3_INS.contains_key(&(insn.id.0 as u32)) {
            None
        } else {
            Some(IllegalInsn)
        }
    };

    let op = (insn.raw & OPCODE_MASK) >> 26;

    match op {
        COP0_OPS => Some(Cop0),
        COP2_OPS => Some(Cop2),
        COP1X_OPS | SPECIAL2_OPS | SPECIAL3_OPS => Some(IllegalInsn),
        _ => None,
    }
    .or_else(check_valid_insn)
}

use capstone::arch::mips::MipsInsn::{self, *};
use std::collections::HashMap;

const MIPS3_INSN: &[MipsInsn] = &[
    MIPS_INS_ADD,
    MIPS_INS_ADDU,
    MIPS_INS_ADDI,
    MIPS_INS_ADDIU,
    MIPS_INS_AND,
    MIPS_INS_ANDI,
    MIPS_INS_BAL,
    MIPS_INS_BC1F,
    MIPS_INS_BC1FL,
    MIPS_INS_BC1T,
    MIPS_INS_BC1TL,
    MIPS_INS_BEQ,
    MIPS_INS_BEQL,
    MIPS_INS_BGEZ,
    MIPS_INS_BGEZAL,
    MIPS_INS_BGEZALL,
    MIPS_INS_BGEZL,
    MIPS_INS_BGTZ,
    MIPS_INS_BGTZL,
    MIPS_INS_BLEZ,
    MIPS_INS_BLEZL,
    MIPS_INS_BLTZ,
    MIPS_INS_BLTZAL,
    MIPS_INS_BLTZALL,
    MIPS_INS_BLTZL,
    MIPS_INS_BNE,
    MIPS_INS_BNEL,
    MIPS_INS_BREAK,
    MIPS_INS_BEQZ,
    MIPS_INS_B,
    MIPS_INS_BNEZ,
    MIPS_INS_CACHE,
    MIPS_INS_CFC1,
    MIPS_INS_CTC1,
    MIPS_INS_CEIL,
    MIPS_INS_CVT,
    MIPS_INS_C,
    MIPS_INS_DADD,
    MIPS_INS_DADDI,
    MIPS_INS_DADDIU,
    MIPS_INS_DADDU,
    MIPS_INS_DDIV,
    MIPS_INS_DDIVU,
    MIPS_INS_DIV,
    MIPS_INS_DIVU,
    MIPS_INS_DMFC1,
    MIPS_INS_DMTC1,
    MIPS_INS_DMUL,
    MIPS_INS_DMULT,
    MIPS_INS_DMULTU,
    MIPS_INS_DSLL,
    MIPS_INS_DSLL32,
    MIPS_INS_DSLLV,
    MIPS_INS_DSRA,
    MIPS_INS_DSRA32,
    MIPS_INS_DSRAV,
    MIPS_INS_DSRL,
    MIPS_INS_DSRL32,
    MIPS_INS_DSRLV,
    MIPS_INS_DSUB,
    MIPS_INS_DSUBU,
    MIPS_INS_ERET,
    MIPS_INS_ABS,
    MIPS_INS_MOV,
    MIPS_INS_MUL,
    MIPS_INS_NEG,
    MIPS_INS_SQRT,
    MIPS_INS_SUB,
    MIPS_INS_J,
    MIPS_INS_JAL,
    MIPS_INS_JALR,
    MIPS_INS_JR,
    MIPS_INS_LB,
    MIPS_INS_LBU,
    MIPS_INS_LD,
    MIPS_INS_LDC1,
    MIPS_INS_LDL,
    MIPS_INS_LDR,
    MIPS_INS_LH,
    MIPS_INS_LHU,
    MIPS_INS_LUI,
    MIPS_INS_LW,
    MIPS_INS_LWC1,
    MIPS_INS_LWL,
    MIPS_INS_LWR,
    MIPS_INS_LWU,
    MIPS_INS_LI,
    MIPS_INS_MFC0,
    MIPS_INS_MFC1,
    MIPS_INS_MFHI,
    MIPS_INS_MFLO,
    MIPS_INS_MTC0,
    MIPS_INS_MTC1,
    MIPS_INS_MTHI,
    MIPS_INS_MTLO,
    MIPS_INS_MULT,
    MIPS_INS_MULTU,
    MIPS_INS_NOR,
    MIPS_INS_NORI,
    MIPS_INS_OR,
    MIPS_INS_ORI,
    MIPS_INS_SB,
    MIPS_INS_SD,
    MIPS_INS_SDC1,
    MIPS_INS_SDL,
    MIPS_INS_SDR,
    MIPS_INS_SH,
    MIPS_INS_SLL,
    MIPS_INS_SLLV,
    MIPS_INS_SLT,
    MIPS_INS_SLTI,
    MIPS_INS_SLTIU,
    MIPS_INS_SLTU,
    MIPS_INS_SRA,
    MIPS_INS_SRAV,
    MIPS_INS_SRL,
    MIPS_INS_SRLV,
    MIPS_INS_SUBU,
    MIPS_INS_SW,
    MIPS_INS_SWC1,
    MIPS_INS_SWL,
    MIPS_INS_SWR,
    MIPS_INS_TEQ,
    MIPS_INS_TEQI,
    MIPS_INS_TGE,
    MIPS_INS_TGEI,
    MIPS_INS_TGEIU,
    MIPS_INS_TGEU,
    MIPS_INS_TLT,
    MIPS_INS_TLTI,
    MIPS_INS_TLTIU,
    MIPS_INS_TLTU,
    MIPS_INS_TNE,
    MIPS_INS_TNEI,
    MIPS_INS_TRUNC,
    MIPS_INS_XOR,
    MIPS_INS_XORI,
    MIPS_INS_NOP,
    MIPS_INS_NEGU,
    MIPS_INS_NOT,
];

use once_cell::sync::Lazy;

static VALID_MIPS3_INS: Lazy<HashMap<u32, MipsInsn>> = Lazy::new(|| {
    MIPS3_INSN
        .iter()
        .map(|insn| (*insn as u32, *insn))
        .collect()
});

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
