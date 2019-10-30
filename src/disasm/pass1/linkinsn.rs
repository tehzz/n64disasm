use crate::disasm::{mipsinsn::*, pass1::Instruction};
use capstone::{arch::mips::MipsOperand, arch::mips::MipsReg::*, prelude::*};
use err_derive::Error;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Error)]
pub enum LinkInsnErr {
    #[error(display = "Missing '{}' in instruction:\n{:#?}", _1, _0)]
    MissingInsnComponent(Instruction, &'static str),
}

#[derive(Debug)]
pub struct LinkState {
    registers: HashMap<RegId, LuiState>,
    pc_delay_slot: DelaySlot,
}

impl LinkState {
    pub fn new() -> Self {
        Self {
            registers: HashMap::with_capacity(32),
            pc_delay_slot: DelaySlot::Inactive,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct LinkedVal {
    value: u32,
    offset: Option<i16>,
    instruction: usize,
}

impl LinkedVal {
    fn new(value: u32, offset: Option<i16>, instruction: usize) -> Self {
        Self {
            value,
            offset,
            instruction,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum LuiResolve {
    Empty,
    Pointer(LinkedVal),
    Immediate(LinkedVal),
    Float(LinkedVal),
}

impl LuiResolve {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            _ => false,
        }
    }
}

impl ::std::iter::IntoIterator for LuiResolve {
    type Item = Self;
    type IntoIter = ::std::iter::Once<Self>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self)
    }
}

impl fmt::Display for LuiResolve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty link...?"),
            Self::Pointer(l) => write!(
                f,
                "Pointer to {:08x} at instruction {}",
                l.value, l.instruction
            ),
            Self::Immediate(l) => write!(
                f,
                "Immediate value {:08x} at instruction {}",
                l.value, l.instruction
            ),
            Self::Float(l) => write!(
                f,
                "Float {} ({:08x}) at instruction {}",
                f32::from_bits(l.value),
                l.value,
                l.instruction
            ),
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum LuiState {
    Upper(RegId, i16, usize),
    Loaded(RegId, u32),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DelaySlot {
    Inactive,
    Queued,
    DelaySlot,
    Resummed,
}

impl DelaySlot {
    // return the next state of an instruction after a "CPU tick"
    fn tick_pc(&self) -> Self {
        match self {
            Self::Inactive => Self::Inactive,
            Self::Queued => Self::DelaySlot,
            Self::DelaySlot => Self::Resummed,
            Self::Resummed => Self::Inactive,
        }
    }
}

pub fn link_instructions<'s, 'i>(
    state: &'s mut LinkState,
    insn: &'i Instruction,
    offset: usize,
) -> Result<Option<impl Iterator<Item = LuiResolve>>, LinkInsnErr> {
    use LinkInsnErr::*;
    use LuiResolve::*;
    use LuiState::*;

    let delay = &mut state.pc_delay_slot;
    let reg_state = &mut state.registers;

    // reset register state on subroutine exit
    *delay = delay.tick_pc();

    if *delay == DelaySlot::Resummed {
        reg_state.clear();
    }

    if insn.jump.is_jrra() {
        *delay = DelaySlot::Queued;
        return Ok(None);
    }

    // otherwise, look for specific instructions that typically indicate pointer or float loads
    let op = insn.id.0;
    match op {
        // Every immediate greater than 16bit in MIPS typically uses this instruction
        // to set the upper 16 bits. So, this has to set the upper bits of a register that
        // will be used in a later instruction as a pointer or float
        INS_LUI => {
            let (reg, imm) = get_lui_ops(&insn)?;
            reg_state.insert(reg, Upper(reg, imm, offset));
            Ok(None)
        }
        // The `addiu` instruction is emitted with a matched `lui` for pointers.
        // The immediate value can be positive or negative
        INS_ADDIU => {
            let (dst, src, imm) = get_dsimm_triple(&insn)?;
            if dst != src {
                return Ok(None);
            }

            Ok(reg_state
                .get_mut(&dst)
                .and_then(|state| match *state {
                    Upper(_reg, upper, prior) => {
                        let ptr = ((upper as i32) << 16) + (imm as i32);
                        let ptr = ptr as u32;
                        *state = Loaded(dst, ptr);

                        Some((ptr, prior))
                    }
                    _ => None,
                })
                .and_then(|(ptr, prior)| {
                    let lui_insn = Pointer(LinkedVal::new(ptr, None, prior));
                    let lower_insn = Pointer(LinkedVal::new(ptr, None, offset));

                    Some(lui_insn.into_iter().chain(lower_insn))
                }))
        }
        // The `ori` instruction is emitted with a matched `lui` for large immediate values
        INS_ORI => {
            let (dst, src, imm) = get_dsimm_triple(&insn)?;
            if dst != src {
                return Ok(None);
            }

            Ok(reg_state
                .get_mut(&dst)
                .and_then(|state| match *state {
                    Upper(_reg, upper, prior) => {
                        let val = ((upper as u32) << 16) | (imm as u16 as u32);
                        *state = Loaded(dst, val);
                        Some((val, prior))
                    }
                    _ => None,
                })
                .and_then(|(val, prior)| {
                    let lui_insn = Immediate(LinkedVal::new(val, None, prior));
                    let lower_insn = Immediate(LinkedVal::new(val, None, offset));

                    Some(lui_insn.into_iter().chain(lower_insn))
                }))
        }
        // Float constants (singles) are loaded by setting the upper bits with a `lui`,
        // and then setting the lower bits with an `ori`, if needed. This instruction
        // then moves the float to cop1
        INS_MTC1 => {
            let src = get_reg_n(&insn.operands, 0)
                .ok_or_else(|| MissingInsnComponent(insn.clone(), "mtc1 source reg"))?;

            if src.0 as u32 == MIPS_REG_ZERO {
                let mtc1_zero = Float(LinkedVal::new(0, None, offset));
                return Ok(Some(mtc1_zero.into_iter().chain(Empty)));
            }

            Ok(reg_state.get_mut(&src).and_then(|state| match *state {
                Upper(_reg, val, prior) => {
                    let val = (val as u32) << 16;
                    let upper = Float(LinkedVal::new(val, None, prior));
                    let mtc1 = Float(LinkedVal::new(val, None, offset));

                    Some(upper.into_iter().chain(mtc1))
                }
                Loaded(_reg, val) => {
                    let mtc1 = Float(LinkedVal::new(val, None, offset));
                    Some(mtc1.into_iter().chain(Empty))
                }
            }))
        }
        // load/store word/half/byte instructions?
        _ => Ok(None), // or, check if register is overwritten?
    }
}

fn get_imm(operands: &[MipsOperand]) -> Option<i16> {
    use MipsOperand::*;

    operands.iter().find_map(|op| {
        if let Imm(i) = op {
            Some(*i as i16)
        } else {
            None
        }
    })
}

fn get_reg_n(operands: &[MipsOperand], n: usize) -> Option<RegId> {
    use MipsOperand::*;

    operands
        .iter()
        .filter_map(|op| if let Reg(id) = op { Some(*id) } else { None })
        .nth(n)
}

/// Get the set of (rd, rs, imm) from an `Instruction`
fn get_dsimm_triple(insn: &Instruction) -> Result<(RegId, RegId, i16), LinkInsnErr> {
    use LinkInsnErr::*;

    let dst = get_reg_n(&insn.operands, 0)
        .ok_or_else(|| MissingInsnComponent(insn.clone(), "dst reg"))?;
    let src = get_reg_n(&insn.operands, 1)
        .ok_or_else(|| MissingInsnComponent(insn.clone(), "src reg"))?;
    let imm =
        get_imm(&insn.operands).ok_or_else(|| MissingInsnComponent(insn.clone(), "immediate"))?;

    Ok((dst, src, imm))
}

/// Get the target register and immediate from a Lui instruction
fn get_lui_ops(insn: &Instruction) -> Result<(RegId, i16), LinkInsnErr> {
    use LinkInsnErr::*;

    let reg = get_reg_n(&insn.operands, 0)
        .ok_or_else(|| MissingInsnComponent(insn.clone(), "lui reg"))?;
    let imm = get_imm(&insn.operands)
        .ok_or_else(|| MissingInsnComponent(insn.clone(), "lui immediate"))?;

    Ok((reg, imm))
}
