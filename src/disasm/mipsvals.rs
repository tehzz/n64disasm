use capstone::arch::mips::MipsInsn::*;
use capstone::arch::mips::MipsReg::*;
use capstone::{InsnId, RegId};

// Useful instructions from Capstone C enum
pub const INS_MOVE: u32 = MIPS_INS_MOVE as u32;
pub const INS_OR: u32 = MIPS_INS_OR as u32;
pub const INS_ADDU: u32 = MIPS_INS_ADDU as u32;

pub const INS_J: u32 = MIPS_INS_J as u32;
pub const INS_JAL: u32 = MIPS_INS_JAL as u32;
pub const INS_BAL: u32 = MIPS_INS_BAL as u32;

pub const INS_LUI: u32 = MIPS_INS_LUI as u32;
pub const INS_ADDIU: u32 = MIPS_INS_ADDIU as u32;
pub const INS_ORI: u32 = MIPS_INS_ORI as u32;
pub const INS_MTC1: u32 = MIPS_INS_MTC1 as u32;

pub const INS_MTC0: u32 = MIPS_INS_MTC0 as u32;
pub const INS_MFC0: u32 = MIPS_INS_MFC0 as u32;

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
pub const INS_LWL: u32 = MIPS_INS_LWL as u32;
pub const INS_LWR: u32 = MIPS_INS_LWR as u32;
pub const INS_LWC1: u32 = MIPS_INS_LWC1 as u32;
pub const INS_LWC2: u32 = MIPS_INS_LWC2 as u32;
pub const INS_LWC3: u32 = MIPS_INS_LWC3 as u32;
pub const INS_SWC1: u32 = MIPS_INS_SWC1 as u32;
pub const INS_SWC2: u32 = MIPS_INS_SWC2 as u32;
pub const INS_SWC3: u32 = MIPS_INS_SWC3 as u32;

pub fn is_grp_load(id: InsnId) -> bool {
    match id.0 {
        INS_LB | INS_LBU | INS_LD | INS_LDL | INS_LDR | INS_LH | INS_LHU | INS_LW | INS_LWU
        | INS_LWL | INS_LWR => true,
        _ => false,
    }
}

// Callee Saved Registers
pub const CALLEE_SAVED_REGS: [RegId; 10] = [
    RegId(MIPS_REG_GP as u16),
    RegId(MIPS_REG_S0 as u16),
    RegId(MIPS_REG_S1 as u16),
    RegId(MIPS_REG_S2 as u16),
    RegId(MIPS_REG_S3 as u16),
    RegId(MIPS_REG_S4 as u16),
    RegId(MIPS_REG_S5 as u16),
    RegId(MIPS_REG_S6 as u16),
    RegId(MIPS_REG_S7 as u16),
    RegId(MIPS_REG_S8 as u16),
];

// Caller Saved Registers (ignoring r0, k0, k1)
pub const CALLER_SAVED_REGS: [RegId; 19] = [
    RegId(MIPS_REG_AT as u16),
    RegId(MIPS_REG_T0 as u16),
    RegId(MIPS_REG_T1 as u16),
    RegId(MIPS_REG_T2 as u16),
    RegId(MIPS_REG_T3 as u16),
    RegId(MIPS_REG_T4 as u16),
    RegId(MIPS_REG_T5 as u16),
    RegId(MIPS_REG_T6 as u16),
    RegId(MIPS_REG_T7 as u16),
    RegId(MIPS_REG_T8 as u16),
    RegId(MIPS_REG_T9 as u16),
    RegId(MIPS_REG_V0 as u16),
    RegId(MIPS_REG_V1 as u16),
    RegId(MIPS_REG_A0 as u16),
    RegId(MIPS_REG_A1 as u16),
    RegId(MIPS_REG_A2 as u16),
    RegId(MIPS_REG_A3 as u16),
    RegId(MIPS_REG_SP as u16),
    RegId(MIPS_REG_RA as u16),
];
