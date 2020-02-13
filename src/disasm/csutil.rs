//! Utilities for dealing with capstone issues and warts
use crate::disasm::{
    instruction::Instruction,
    mipsvals::{INS_ADDU, INS_MFC0, INS_MOVE, INS_MTC0, INS_OR, MIPS3_INSNS},
};
use capstone::{arch::mips::MipsOperand, arch::mips::MipsReg::*, prelude::*};
use once_cell::sync::Lazy;
use std::collections::HashSet;

/// Capstone does not have a MIPS3 disassembly target, so this `HashSet` is
/// here to check if a disassembled instruction is actually a mips3 instruction,
/// or if it is an instruction from a later instruction set.
pub static VALID_MIPS3_INSNS: Lazy<HashSet<u32>> =
    Lazy::new(|| MIPS3_INSNS.iter().map(|insn| *insn as u32).collect());

pub fn get_instance() -> Result<Capstone, capstone::Error> {
    Capstone::new()
        .mips()
        .detail(true)
        .mode(arch::mips::ArchMode::Mips64)
        .endian(capstone::Endian::Big)
        .build()
}

pub fn correct_insn(insn: &mut Instruction) {
    match insn.id.0 {
        INS_MOVE => fix_move(insn),
        INS_MTC0 | INS_MFC0 => fix_cop0_moves(insn),
        _ => (),
    };
}

/// capstone `move d, s` instructions should be either an `or d, s, $zero`
/// or an `addu d, s, $zero`. This converts the `Instruction` back to the
/// more precise form
fn fix_move(insn: &mut Instruction) {
    // MIPS `or` insn:       0000 00ss ssst tttt dddd d000 0010 0101  => 37
    // MIPS 'addu' insn:     0000 00ss ssst tttt dddd d000 0010 0001  => 33
    const INSN_MASK: u32 = 0b1111_1100_0000_0000_0000_0111_1111_1111;

    assert!(
        insn.id.0 == INS_MOVE,
        "tried to move fix a not move instruction\n{:?}",
        &insn
    );

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

/// Capstone/LLVM doesn't use the proper register for the mtc0 and mfc0 instructions
/// This converts to raw C0 register numbers:
fn fix_cop0_moves(insn: &mut Instruction) {
    assert!(insn.id.0 == INS_MTC0 || insn.id.0 == INS_MFC0);

    //                                 rt    rd
    // mfc0:            010000 00000 xxxxx xxxxx 00000000000
    // mtc0:            010000 00100 xxxxx xxxxx 00000000000
    // cop0 register is always second (rd); eg
    // mfc0 $t4, Cause
    // mtc0 $t4, Cause
    let rd = (insn.raw >> 11) & 0b11111;
    assert!(rd < 31, "Found rd in cop0 move instruction greater than 31");

    if let Some(ref mut op) = insn.op_str {
        let first_op_end = op.find(',').expect("comma separated operands");
        let rd_str = format!(", ${}", rd);
        op.replace_range(first_op_end.., &rd_str);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ADDU_INSNS: [u8; 2 * 4] = [
        0x01, 0x40, 0x48, 0x21, // addu t1, t2, r0
        0x03, 0x00, 0x80, 0x21, // addu s0, t8, r0
    ];

    const OR_INSNS: [u8; 2 * 4] = [
        0x03, 0x00, 0x80, 0x25, // or s0, t8, r0
        0x00, 0x80, 0x10, 0x25, // or v0, a0, r0
    ];

    const MOV_COP0_INSNS: [u8; 6 * 4] = [
        0x40, 0x0c, 0x60, 0x00, // mfc0 $t4, $4
        0x40, 0x8c, 0x60, 0x00, // mtc0 $t4, $4
        0x40, 0x9b, 0x60, 0x00, // mtc0 $k1, $4
        0x40, 0x08, 0x68, 0x00, // mfc0 $t0, $5
        0x40, 0x0b, 0x00, 0x00, // mfc0 $t3, $0
        0x40, 0x80, 0x28, 0x00, // mtc0 $zero, $5
    ];

    const MOV_COP0_MNEM: [(&'static str, &'static str); 6] = [
        ("mfc0", "$t4, $12"),
        ("mtc0", "$t4, $12"),
        ("mtc0", "$k1, $12"),
        ("mfc0", "$t0, $13"),
        ("mfc0", "$t3, $0"),
        ("mtc0", "$zero, $5"),
    ];

    fn raw_to_instruction(raw: &[u8]) -> Vec<Instruction> {
        let cs = get_instance().expect("working Capstone");

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

    #[test]
    fn test_cop0_moves() {
        let iter = raw_to_instruction(&MOV_COP0_INSNS)
            .into_iter()
            .zip(&MOV_COP0_MNEM);

        for (mut insn, parts) in iter {
            fix_cop0_moves(&mut insn);
            assert_eq!(&insn.mnemonic, parts.0, "perserve cop0 instruction");
            let op_str = insn.op_str.expect("operands for cop0 move instruction");
            assert_eq!(op_str, parts.1);
        }
    }
}
