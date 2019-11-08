use crate::disasm::pass1::JumpKind;
use crate::disasm::pass1::LinkedVal;
use arrayvec::ArrayString;
use capstone::{arch::mips::MipsOperand, prelude::*, Insn};
use err_derive::Error;
use std::convert::TryInto;

#[derive(Debug, Error)]
pub enum InsnParseErr {
    #[error(display = "MIPS opcode mnemonic longer than 16 bytes: {}", _0)]
    LongMnem(String),
    #[error(display = "MIPS instruction not four bytes <{:x?}>", _0)]
    IllegalInsn(Vec<u8>, #[error(source)] ::std::array::TryFromSliceError),
    #[error(display = "Problem with capstone disassembly")]
    Capstone(#[error(source)] capstone::Error),
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub id: capstone::InsnId,
    pub vaddr: u32,
    pub raw: u32,
    pub mnemonic: ArrayString<[u8; 16]>,
    pub op_str: Option<String>,
    pub operands: Vec<MipsOperand>,
    pub new_line: bool,
    pub jump: JumpKind,
    pub linked: LinkedVal,
}

impl Instruction {
    pub fn from_components(insn: &Insn, detail: &InsnDetail) -> Result<Self, InsnParseErr> {
        use InsnParseErr::*;

        let mnemonic = insn.mnemonic().expect("MIPS Opcode Mnemonic");

        Ok(Self {
            id: insn.id(),
            vaddr: insn.address() as u32,
            raw: insn
                .bytes()
                .try_into()
                .map(u32::from_be_bytes)
                .map_err(|e| IllegalInsn(insn.bytes().to_vec(), e))?,
            mnemonic: ArrayString::from(mnemonic).map_err(|_| LongMnem(mnemonic.to_string()))?,
            op_str: insn.op_str().map(str::to_string),
            operands: detail
                .arch_detail()
                .mips()
                .expect("All decompiled instructions should be MIPS")
                .operands()
                .collect(),
            new_line: false,
            jump: JumpKind::from((insn, detail)),
            linked: LinkedVal::Empty,
        })
    }
}
