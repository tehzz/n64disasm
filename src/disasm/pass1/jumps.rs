use crate::disasm::mipsvals::*;
use capstone::{
    arch::mips::{MipsOperand, MipsReg::*},
    prelude::*,
    Insn,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JumpKind {
    None,
    Branch(u32),
    BAL(u32),
    Jump(u32),
    JAL(u32),
    JumpRegister(RegId),
}

impl JumpKind {
    pub fn is_jrra(&self) -> bool {
        match self {
            Self::JumpRegister(r) => r.0 as u32 == MIPS_REG_RA,
            _ => false,
        }
    }

    pub fn is_jal(&self) -> bool {
        match self {
            Self::JAL(_) => true,
            _ => false,
        }
    }
}

impl From<(&Insn<'_>, &InsnDetail<'_>)> for JumpKind {
    fn from((insn, details): (&Insn, &InsnDetail)) -> Self {
        use capstone::arch::mips::MipsInsnGroup::*;

        // for some reason, the MIPS `j`,`jal`, `jalr`, etc. instructions are not in the jump group...
        // in fact, they have no specific group of their own.
        if !details.groups().any(|g| g.0 as u32 == MIPS_GRP_JUMP)
            && insn.id().0 != INS_JAL
            && insn.id().0 != INS_J
        {
            return Self::None;
        }

        let imm = details
            .arch_detail()
            .mips()
            .expect("All decompiled instructions should be MIPS")
            .operands()
            .find_map(|op| match op {
                MipsOperand::Imm(val) => Some(val as u32),
                _ => None,
            });

        let reg = details
            .arch_detail()
            .mips()
            .expect("All decompiled instructions should be MIPS")
            .operands()
            .find_map(|op| match op {
                MipsOperand::Reg(r) => Some(r),
                _ => None,
            });

        if let Some(imm) = imm {
            match insn.id().0 {
                INS_J => JumpKind::Jump(imm),
                INS_JAL => JumpKind::JAL(imm),
                INS_BAL => JumpKind::BAL(imm),
                _ => JumpKind::Branch(imm),
            }
        } else if let Some(jr_target) = reg {
            // catch `jr XX` and `jalr XX`, but I don't think they make it here
            // do to the above noted issue with capstone
            JumpKind::JumpRegister(jr_target)
        } else {
            unreachable!("Not all branch/jump types covered?");
        }
    }
}
