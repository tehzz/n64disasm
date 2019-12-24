//! Utilities for dealing with capstone issues and warts
use crate::disasm::{
    instruction::Instruction,
    mipsvals::{INS_ADDU, INS_MOVE, INS_OR},
};
use capstone::{arch::mips::MipsOperand, arch::mips::MipsReg::*, prelude::*};

pub fn get_instance() -> Result<Capstone, capstone::Error> {
    Capstone::new()
        .mips()
        .detail(true)
        .mode(arch::mips::ArchMode::Mips64)
        .endian(capstone::Endian::Big)
        .build()
}

/// capstone `move d, s` instructions should be either an `or d, s, $zero`
/// or an `addu d, s, $zero`. This converts the `Instruction` back to the
/// more precise form
pub fn fix_move(insn: &mut Instruction) {
    // MIPS `or` insn:       0000 00ss ssst tttt dddd d000 0010 0101  => 37
    // MIPS 'addu' insn:     0000 00ss ssst tttt dddd d000 0010 0001  => 33
    const INSN_MASK: u32 = 0b1111_1100_0000_0000_0000_0111_1111_1111;

    if insn.id.0 != INS_MOVE {
        return;
    }

    insn.mnemonic.clear();
    match insn.raw & INSN_MASK {
        33 => {
            insn.id = InsnId(INS_ADDU);
            insn.mnemonic.push_str("addu");
        }
        37 => {
            insn.id = InsnId(INS_OR);
            insn.mnemonic.push_str("or");
        }
        _ => panic!("Unknown 'move' instruction: {:08x}", insn.raw),
    }

    if let Some(ref mut op) = insn.op_str {
        op.push_str(", $zero");
    }
    let zero_operand = MipsOperand::Reg(RegId(MIPS_REG_ZERO as u16));
    insn.operands.push(zero_operand);
}

#[cfg(test)]
mod test {
    use super::*;

    const ADDU_INSNS: [u8; 2 * 4] = [
        0x01,0x40,0x48,0x21, // addu t1, t2, r0
        0x03,0x00,0x80,0x21, // addu s0, t8, r0
    ];

    const OR_INSNS: [u8; 2 * 4] = [
        0x03,0x00,0x80,0x25, // or s0, t8, r0
        0x00,0x80,0x10,0x25, // or v0, a0, r0
    ];

    fn raw_to_instruction(raw: &[u8]) -> Vec<Instruction> {
        let cs = get_instance().expect("working Capstone");

        let output = cs.disasm_all(raw, 0x80004000)
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
    fn move_to_addu() {
        for mut insn in raw_to_instruction(&ADDU_INSNS) {
            assert_eq!(insn.id.0, INS_MOVE, "`addu` wasn't disassembled as `move`");
            fix_move(&mut insn);
            assert_eq!(
                insn.id.0, INS_ADDU,
                "`move` instruction not converted back to `addu`"
            );
        }
    }

    #[test]
    fn move_to_or() {
        for mut insn in raw_to_instruction(&OR_INSNS) {
            assert_eq!(insn.id.0, INS_MOVE, "`or` wasn't disassembled as `move`");
            fix_move(&mut insn);
            assert_eq!(
                insn.id.0, INS_OR,
                "`move` instruction not converted back to `or`"
            );
        }
    }
}
