use capstone::arch::mips::MipsInsn::*;

// Useful instructions from Capstone C enum
pub const INS_J: u32 = MIPS_INS_J as u32;
pub const INS_JAL: u32 = MIPS_INS_JAL as u32;
pub const INS_BAL: u32 = MIPS_INS_BAL as u32;
pub const INS_LUI: u32 = MIPS_INS_LUI as u32;
pub const INS_ADDIU: u32 = MIPS_INS_ADDIU as u32;
pub const INS_ADDI: u32 = MIPS_INS_ADDI as u32;
pub const INS_ORI: u32 = MIPS_INS_ORI as u32;
pub const INS_MTC1: u32 = MIPS_INS_MTC1 as u32;
