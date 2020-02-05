use capstone::arch::mips::MipsInsn::{self, *};
use capstone::arch::mips::MipsReg::*;
use capstone::{InsnId, RegId};

// Useful instructions from Capstone C enum
pub const INS_NOP: u32 = MIPS_INS_NOP as u32;
pub const INS_MOVE: u32 = MIPS_INS_MOVE as u32;
pub const INS_OR: u32 = MIPS_INS_OR as u32;
pub const INS_ADDU: u32 = MIPS_INS_ADDU as u32;

pub const INS_J: u32 = MIPS_INS_J as u32;
pub const INS_JAL: u32 = MIPS_INS_JAL as u32;
pub const INS_BAL: u32 = MIPS_INS_BAL as u32;
pub const INS_B: u32 = MIPS_INS_B as u32;
pub const INS_BC1T: u32 = MIPS_INS_BC1T as u32;
pub const INS_BC1TL: u32 = MIPS_INS_BC1TL as u32;
pub const INS_BC1F: u32 = MIPS_INS_BC1F as u32;
pub const INS_BC1FL: u32 = MIPS_INS_BC1FL as u32;

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

// Valid mipsIII instructions since capstone doesn't have a working mipsIII mode
pub const MIPS3_INSN: &[MipsInsn] = &[
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
