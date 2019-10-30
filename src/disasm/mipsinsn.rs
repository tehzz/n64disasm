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

pub const INS_SD: u32 = MIPS_INS_SD as u32;
pub const INS_SW: u32 = MIPS_INS_SW as u32;
pub const INS_SH: u32 = MIPS_INS_SH as u32;
pub const INS_SB: u32 = MIPS_INS_SB as u32;
pub const INS_LB: u32 = MIPS_INS_LB as u32;
pub const INS_LBU: u32 = MIPS_INS_LBU as u32;
pub const INS_LD: u32 = MIPS_INS_LD as u32;
pub const INS_LDL: u32 = MIPS_INS_LDL as u32;
pub const INS_LDR: u32 = MIPS_INS_LDR as u32;
pub const INS_LH: u32 = MIPS_INS_LH as u32;
pub const INS_LHU: u32 = MIPS_INS_LHU as u32;
pub const INS_LW: u32 = MIPS_INS_LW as u32;
pub const INS_LWU: u32 = MIPS_INS_LWU as u32;
pub const INS_LWC1: u32 = MIPS_INS_LWC1 as u32;
pub const INS_LWC2: u32 = MIPS_INS_LWC2 as u32;
pub const INS_LWC3: u32 = MIPS_INS_LWC3 as u32;
pub const INS_SWC1: u32 = MIPS_INS_SWC1 as u32;
pub const INS_SWC2: u32 = MIPS_INS_SWC2 as u32;
pub const INS_SWC3: u32 = MIPS_INS_SWC3 as u32;
