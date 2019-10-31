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
            registers: HashMap::with_capacity(64),
            pc_delay_slot: DelaySlot::Inactive,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Link {
    pub value: u32,
    pub instruction: usize,
}

impl Link {
    fn new(value: u32, instruction: usize) -> Self {
        Self { value, instruction }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum LinkedVal {
    Empty,
    Pointer(Link),
    PtrOff(Link, i16),
    Immediate(Link),
    Float(Link),
}

impl LinkedVal {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            _ => false,
        }
    }
    pub fn get_link(&self) -> Option<Link> {
        match self {
            Self::Empty => None,
            Self::Pointer(l) => Some(*l),
            Self::PtrOff(l, _) => Some(*l),
            Self::Immediate(l) => Some(*l),
            Self::Float(l) => Some(*l),
        }
    }
}

impl ::std::iter::IntoIterator for LinkedVal {
    type Item = Self;
    type IntoIter = ::std::iter::Once<Self>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self)
    }
}

impl fmt::Display for LinkedVal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty link...?"),
            Self::Pointer(l) => write!(
                f,
                "Pointer to {:08x} at instruction {}",
                l.value, l.instruction
            ),
            Self::PtrOff(l, o) => write!(
                f,
                "Pointer to {:08x} with offset {} at instruction {}",
                l.value, o, l.instruction
            ),
            Self::Immediate(l) => write!(
                f,
                "Immediate value {:08x} at instruction {}",
                l.value, l.instruction
            ),
            Self::Float(l) => write!(
                f,
                "Float {:.5} ({:08x}) at instruction {}",
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
) -> Result<Option<impl Iterator<Item = LinkedVal>>, LinkInsnErr> {
    use LinkInsnErr::*;
    use LinkedVal::*;
    use LuiState::*;

    // helper functions for combining 16-bit intermediates
    let add_imms = |a, b| (((a as i32) << 16) + (b as i32)) as u32;
    let or_imms = |a, b| ((a as u32) << 16) | (b as u16 as u32);

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
    match insn.id.0 {
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

            Ok(reg_state.get_mut(&dst).and_then(|state| match *state {
                Upper(_reg, upper, prior) => {
                    let ptr = add_imms(upper, imm);
                    *state = Loaded(dst, ptr);

                    let lui_insn = Pointer(Link::new(ptr, prior));
                    let lower_insn = Pointer(Link::new(ptr, offset));
                    Some(lui_insn.into_iter().chain(lower_insn))
                }
                // TODO: either calculate a new pointer, or reset state
                Loaded(..) => None,
            }))
        }
        // The `ori` instruction is emitted with a matched `lui` for large immediate values
        INS_ORI => {
            let (dst, src, imm) = get_dsimm_triple(&insn)?;
            if dst != src {
                return Ok(None);
            }

            Ok(reg_state.get_mut(&dst).and_then(|state| match *state {
                Upper(_reg, upper, prior) => {
                    let val = or_imms(upper, imm);
                    *state = Loaded(dst, val);

                    let lui_insn = Immediate(Link::new(val, prior));
                    let lower_insn = Immediate(Link::new(val, offset));
                    Some(lui_insn.into_iter().chain(lower_insn))
                }
                // TODO: either calculate a new offset, or reset state
                Loaded(..) => None,
            }))
        }
        // Float constants (singles) are loaded by setting the upper bits with a `lui`,
        // and then setting the lower bits with an `ori`, if needed. This instruction
        // then moves the float to cop1
        INS_MTC1 => {
            let src = get_reg_n(&insn.operands, 0)
                .ok_or_else(|| MissingInsnComponent(insn.clone(), "mtc1 source reg"))?;

            if src.0 as u32 == MIPS_REG_ZERO {
                let mtc1_zero = Float(Link::new(0, offset));
                return Ok(Some(mtc1_zero.into_iter().chain(Empty)));
            }

            Ok(reg_state.get_mut(&src).and_then(|state| match *state {
                Upper(_reg, val, prior) => {
                    let val = (val as u32) << 16;
                    let upper = Float(Link::new(val, prior));
                    let mtc1 = Float(Link::new(val, offset));

                    Some(upper.into_iter().chain(mtc1))
                }
                Loaded(_reg, val) => {
                    let mtc1 = Float(Link::new(val, offset));
                    Some(mtc1.into_iter().chain(Empty))
                }
            }))
        }
        // If a pointer is deferenced, the lower 16bit can be embedded in a load or store
        // operation. If there are multiple uses of a base pointer, the full pointer
        // can be loaded into a register and then offset by the load/store.
        INS_SD | INS_SW | INS_SH | INS_SB | INS_LB | INS_LBU | INS_LH | INS_LHU | INS_LW
        | INS_LWU | INS_LWC1 | INS_LWC2 | INS_LWC3 | INS_SWC1 | INS_SWC2 | INS_SWC3 | INS_LD
        | INS_LDL | INS_LDR => {
            let (base, imm) = get_mem_offset(&insn)?;

            Ok(reg_state.get_mut(&base).and_then(|state| match *state {
                Upper(reg, upper, prior) => {
                    let ptr = add_imms(upper, imm);
                    *state = Loaded(reg, ptr);

                    let lui = Pointer(Link::new(ptr, prior));
                    let mem = Pointer(Link::new(ptr, prior));
                    Some(lui.into_iter().chain(mem))
                }
                Loaded(_reg, ptr) => {
                    let mem = PtrOff(Link::new(ptr, offset), imm);
                    Some(mem.into_iter().chain(Empty))
                }
            }))
        }
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
    use LinkInsnErr::MissingInsnComponent as IErr;

    let dst = get_reg_n(&insn.operands, 0).ok_or_else(|| IErr(insn.clone(), "dst reg"))?;
    let src = get_reg_n(&insn.operands, 1).ok_or_else(|| IErr(insn.clone(), "src reg"))?;
    let imm = get_imm(&insn.operands).ok_or_else(|| IErr(insn.clone(), "immediate"))?;

    Ok((dst, src, imm))
}

/// Get the target register and immediate from a Lui instruction
fn get_lui_ops(insn: &Instruction) -> Result<(RegId, i16), LinkInsnErr> {
    use LinkInsnErr::MissingInsnComponent as IErr;

    let reg = get_reg_n(&insn.operands, 0).ok_or_else(|| IErr(insn.clone(), "lui reg"))?;
    let imm = get_imm(&insn.operands).ok_or_else(|| IErr(insn.clone(), "lui immediate"))?;

    Ok((reg, imm))
}

/// Get the base register and offset for a load or store instruction
fn get_mem_offset(insn: &Instruction) -> Result<(RegId, i16), LinkInsnErr> {
    use LinkInsnErr::MissingInsnComponent as IErr;
    use MipsOperand::Mem;

    insn.operands
        .iter()
        .find_map(|op| {
            if let Mem(mem) = op {
                Some((mem.base(), mem.disp() as i16))
            } else {
                None
            }
        })
        .ok_or_else(|| IErr(insn.clone(), "mem info for load or store"))
}
