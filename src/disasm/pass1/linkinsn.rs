use crate::disasm::{mipsvals::*, pass1::Instruction};
use capstone::{arch::mips::MipsReg::*, prelude::*};
use err_derive::Error;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Error)]
pub enum LinkInsnErr {
    #[error(display = "Missing '{}' in instruction:\n{:#?}", _1, _0)]
    MissingInsnComponent(Instruction, &'static str),
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
pub enum LinkedVal {
    Empty,
    Pointer(Link),
    PtrLui(Link),
    PtrEmbed(Link),
    PtrOff(Link, i16),
    Immediate(Link),
    ImmLui(Link),
    Float(Link),
    FloatLoad(Link),
    FloatPtr(Link),
    DoublePtr(Link),
}

#[derive(Debug, Copy, Clone)]
enum LuiState {
    Upper(RegId, i16, usize),
    Loaded(RegId, u32),
    ReadInto(RegId),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DelaySlot {
    Inactive,
    QueuedReturn,
    DelayReturn,
    NewRoutine,
    QueuedCall,
    DelayCall,
    BackFromCall,
}

impl DelaySlot {
    // return the next state of an instruction after a "CPU tick"
    fn tick_pc(self) -> Self {
        match self {
            Self::Inactive => Self::Inactive,
            Self::QueuedReturn => Self::DelayReturn,
            Self::DelayReturn => Self::NewRoutine,
            Self::NewRoutine => Self::Inactive,
            Self::QueuedCall => Self::DelayCall,
            Self::DelayCall => Self::BackFromCall,
            Self::BackFromCall => Self::Inactive,
        }
    }
}

/// Check for any links between `insn` and prior `instructions`.
/// After any links have been resolved, store and return a reference to `insn`.
pub fn link_instructions<'a>(
    state: &mut LinkState,
    insn: Instruction,
    offset: usize,
    instructions: &'a mut Vec<Instruction>,
) -> Result<&'a Instruction, LinkInsnErr> {
    let maybe_links = generate_insn_links(state, &insn, offset)?;

    instructions.push(insn);

    if let Some(links) = maybe_links {
        for link in links.filter(LinkedVal::is_not_empty) {
            let insn_offset = link.get_link().expect("no empty linked values").instruction;

            instructions[insn_offset].linked = link;
        }
    }

    let last_insn = instructions
        .last()
        .expect("always >1 instruction when linking");

    Ok(last_insn)
}

// helper functions for combining 16-bit intermediates
fn add_imms(u: i16, l: i16) -> u32 {
    (((u as i32) << 16) + (l as i32)) as u32
}
fn or_imms(u: i16, l: i16) -> u32 {
    ((u as u32) << 16) | (l as u16 as u32)
}

type LinksIter = Result<
    Option<std::iter::Chain<std::iter::Once<LinkedVal>, std::iter::Once<LinkedVal>>>,
    LinkInsnErr,
>;

// TODO: have an instruction limit (<90?) for pointers just in case
fn generate_insn_links(state: &mut LinkState, insn: &Instruction, offset: usize) -> LinksIter {
    use LinkInsnErr::*;
    use LinkedVal::*;
    use LuiState::*;

    let delay = &mut state.pc_delay_slot;
    let reg_state = &mut state.registers;

    // reset register state on subroutine exit or when calling subroutine
    *delay = delay.tick_pc();

    match delay {
        DelaySlot::NewRoutine => reg_state.clear(),
        DelaySlot::BackFromCall => reset_temp_reg(reg_state),
        _ => (),
    };

    if insn.jump.is_jrra() {
        *delay = DelaySlot::QueuedReturn;
        return Ok(None);
    }

    if insn.jump.is_jal() {
        *delay = DelaySlot::QueuedCall;
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

            let links = reg_state.get_mut(&dst).and_then(|state| match *state {
                Upper(_reg, upper, prior) => {
                    let ptr = add_imms(upper, imm);
                    *state = Loaded(dst, ptr);

                    let lui_insn = PtrLui(Link::new(ptr, prior));
                    let lower_insn = Pointer(Link::new(ptr, offset));
                    Some(lui_insn.into_iter().chain(lower_insn))
                }
                // Reuse of previously loaded upper, probably.
                Loaded(_reg, _val) => None,
                // Actual computation on a loaded value, probably
                ReadInto(..) => None,
            });

            Ok(links)
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

                    let lui_insn = ImmLui(Link::new(val, prior));
                    let lower_insn = Immediate(Link::new(val, offset));
                    Some(lui_insn.into_iter().chain(lower_insn))
                }
                // TODO: either calculate a new offset, or reset state
                Loaded(..) => None,
                // Actual computation on a loaded value, probably
                ReadInto(..) => None,
            }))
        }
        // Float constants (singles) are loaded by setting the upper bits with a `lui`,
        // and then setting the lower bits with an `ori`, if needed. This instruction
        // then moves the float to cop1
        INS_MTC1 => {
            let src = insn
                .get_reg_n(0)
                .ok_or_else(|| MissingInsnComponent(insn.clone(), "mtc1 source reg"))?;

            if src.0 as u32 == MIPS_REG_ZERO {
                let mtc1_zero = Float(Link::new(0, offset));
                return Ok(Some(mtc1_zero.into_iter().chain(Empty)));
            }

            Ok(reg_state.get_mut(&src).and_then(|state| match *state {
                Upper(_reg, val, prior) => {
                    let val = (val as u32) << 16;
                    let upper = Float(Link::new(val, prior));
                    let mtc1 = FloatLoad(Link::new(val, offset));

                    Some(upper.into_iter().chain(mtc1))
                }
                Loaded(_reg, val) => {
                    // reset the ori instructions...?
                    let mtc1 = FloatLoad(Link::new(val, offset));
                    Some(mtc1.into_iter().chain(Empty))
                }
                // pointer was deferenced to load something into cop1.
                // could be a float constant, or an integer to be converted
                ReadInto(..) => None,
            }))
        }
        // If a pointer is deferenced, the lower 16bit can be embedded in a load or store
        // operation. If there are multiple uses of a base pointer, the full pointer
        // can be loaded into a register and then offset by the load/store.
        INS_SD | INS_SW | INS_SH | INS_SB | INS_LB | INS_LBU | INS_LH | INS_LHU | INS_LW
        | INS_LWU | INS_LWC2 | INS_LWC3 | INS_SWC1 | INS_SWC2 | INS_SWC3 | INS_LD | INS_LDC2
        | INS_LDC3 | INS_LDL | INS_LDR | INS_LWL | INS_LWR => {
            let links = link_ptr(&insn, offset, &reg_state, PtrEmbed)?;

            // reset the state of the register used for the load,
            // This may change the state set above if dst == base
            // which is needed to show that this register is now dirty.
            if is_grp_load(insn.id) {
                let (dst, _base, _imm) = get_mem_offset(insn)?;

                if let Some(state) = reg_state.get_mut(&dst) {
                    *state = ReadInto(dst);
                }
            }

            Ok(links)
        }
        // Pointer to float
        INS_LWC1 => link_ptr(&insn, offset, &reg_state, FloatPtr),
        // Pointer to double
        INS_LDC1 => link_ptr(&insn, offset, &reg_state, DoublePtr),
        // ignore other instructions
        _ => Ok(None), // or, maybe check if register is overwritten?
    }
}

// Reset the caller saved registers when calling a subroutine
fn reset_temp_reg(state: &mut HashMap<RegId, LuiState>) {
    for reg in CALLER_SAVED_REGS.iter() {
        state.remove(reg);
    }
}

fn link_ptr(
    insn: &Instruction,
    insn_offset: usize,
    reg_state: &HashMap<RegId, LuiState>,
    ptr_kind: fn(Link) -> LinkedVal,
) -> LinksIter {
    use LinkedVal::*;
    use LuiState::*;

    let (_dst, base, disp) = get_mem_offset(insn)?;
    let links = reg_state.get(&base).and_then(|state| match *state {
        Upper(_reg, upper, prior) => {
            let ptr = add_imms(upper, disp);

            let lui = PtrLui(Link::new(ptr, prior));
            let mem = ptr_kind(Link::new(ptr, insn_offset));

            Some(lui.into_iter().chain(mem))
        }
        Loaded(_reg, ptr) => {
            let mem = PtrOff(Link::new(ptr, insn_offset), disp);

            Some(mem.into_iter().chain(Empty))
        }
        ReadInto(..) => None,
    });

    Ok(links)
}

/// Get the set of (rd, rs, imm) from an `Instruction`
fn get_dsimm_triple(insn: &Instruction) -> Result<(RegId, RegId, i16), LinkInsnErr> {
    use LinkInsnErr::MissingInsnComponent as IErr;

    let dst = insn
        .get_reg_n(0)
        .ok_or_else(|| IErr(insn.clone(), "dst reg"))?;
    let src = insn
        .get_reg_n(1)
        .ok_or_else(|| IErr(insn.clone(), "src reg"))?;
    let imm = insn
        .get_imm()
        .ok_or_else(|| IErr(insn.clone(), "immediate"))?;

    Ok((dst, src, imm))
}

/// Get the target register and immediate from a Lui instruction
fn get_lui_ops(insn: &Instruction) -> Result<(RegId, i16), LinkInsnErr> {
    use LinkInsnErr::MissingInsnComponent as IErr;

    let reg = insn
        .get_reg_n(0)
        .ok_or_else(|| IErr(insn.clone(), "lui reg"))?;
    let imm = insn
        .get_imm()
        .ok_or_else(|| IErr(insn.clone(), "lui immediate"))?;

    Ok((reg, imm))
}

/// Get the base register and offset for a load or store instruction
fn get_mem_offset(insn: &Instruction) -> Result<(RegId, RegId, i16), LinkInsnErr> {
    use LinkInsnErr::MissingInsnComponent as IErr;

    let dst = insn
        .get_reg_n(0)
        .ok_or_else(|| IErr(insn.clone(), "dst for load or store"))?;

    let (base, disp) = insn
        .get_mem_op()
        .ok_or_else(|| IErr(insn.clone(), "mem info for load or store"))?;

    Ok((dst, base, disp))
}

impl LinkedVal {
    pub fn is_not_empty(&self) -> bool {
        match self {
            Self::Empty => false,
            _ => true,
        }
    }
    pub fn get_link(&self) -> Option<Link> {
        match self {
            Self::Empty => None,
            Self::Pointer(l) => Some(*l),
            Self::PtrLui(l) => Some(*l),
            Self::PtrEmbed(l) => Some(*l),
            Self::PtrOff(l, _) => Some(*l),
            Self::Immediate(l) => Some(*l),
            Self::ImmLui(l) => Some(*l),
            Self::Float(l) => Some(*l),
            Self::FloatLoad(l) => Some(*l),
            Self::FloatPtr(l) => Some(*l),
            Self::DoublePtr(l) => Some(*l),
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
            Self::PtrLui(l) => write!(
                f,
                "Upper load of pointer to {:08x} at instruction {}",
                l.value, l.instruction
            ),
            Self::PtrEmbed(l) => write!(
                f,
                "Embedded lower of pointer to {:08x} at instruction {}",
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
            Self::ImmLui(l) => write!(
                f,
                "Upper load of immediate value {:08x} at instruction {}",
                l.value, l.instruction
            ),
            Self::Float(l) => write!(
                f,
                "Float {:.5} ({:08x}) at instruction {}",
                f32::from_bits(l.value),
                l.value,
                l.instruction
            ),
            Self::FloatLoad(l) => write!(
                f,
                "Use of float {:.5} ({:08x}) at instruction {}",
                f32::from_bits(l.value),
                l.value,
                l.instruction
            ),
            Self::FloatPtr(l) => write!(
                f,
                "Pointer {:08x} to float at instruction {}",
                l.value, l.instruction
            ),
            Self::DoublePtr(l) => write!(
                f,
                "Pointer {:08x} to double at instruction {}",
                l.value, l.instruction
            ),
        }
    }
}
