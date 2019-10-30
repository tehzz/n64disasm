use crate::config::Config;
use crate::disasm::{CodeBlock, Label};
use arrayvec::ArrayString;
use capstone::{
    arch::mips::{MipsInsn::*, MipsOperand},
    prelude::*,
    Insn,
};
use err_derive::Error;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

// Useful instructions from Capstone C enum
const INS_J: u32 = MIPS_INS_J as u32;
const INS_JAL: u32 = MIPS_INS_JAL as u32;
const INS_BAL: u32 = MIPS_INS_BAL as u32;
const INS_LUI: u32 = MIPS_INS_LUI as u32;
const INS_ADDIU: u32 = MIPS_INS_ADDIU as u32;
const INS_ADDI: u32 = MIPS_INS_ADDI as u32;
const INS_ORI: u32 = MIPS_INS_ORI as u32;
const INS_MTC1: u32 = MIPS_INS_MTC1 as u32;

#[derive(Debug, Error)]
pub enum Pass1Error {
    #[error(display = "Missing '{}' in instruction:\n{:#?}", _1, _0)]
    MissingInsnComponent(Instruction, &'static str),
    #[error(display = "LUI instruction missing {}:\n{:#?}", _1, _0)]
    MalformedLUI(Instruction, &'static str),
    #[error(display = "MIPS opcode mnemonic longer than 16 bytes: {}", _0)]
    LongMnem(String),
    #[error(
        display = "Expected a MIPS instruction of four bytes, received <{:x?}>",
        _0
    )]
    IllegalInsn(Vec<u8>, #[error(source)] ::std::array::TryFromSliceError),
    #[error(display = "Problem reading ROM in pass 1 disassembly")]
    Io(#[error(source)] ::std::io::Error),
    #[error(display = "Problem with capstone disassembly")]
    Capstone(#[error(source)] capstone::Error),
}

pub fn pass1(config: Config, rom: &Path) -> Result<(), Pass1Error> {
    let Config {
        blocks: config_blocks,
        ..
    } = config;
    let cs = Capstone::new()
        .mips()
        .detail(true)
        .mode(arch::mips::ArchMode::Mips64)
        .endian(capstone::Endian::Big)
        .build()?;

    let mut rom = File::open(rom)?;
    let read_rom = |block: CodeBlock| -> io::Result<(CodeBlock, Vec<u8>)> {
        let CodeBlock {
            rom_start: start,
            rom_end: end,
            ..
        } = block;
        let size = (end - start) as usize;
        let mut buf = vec![0u8; size];

        rom.seek(SeekFrom::Start(start as u64))?;
        rom.read_exact(&mut buf)?;

        Ok((block, buf))
    };

    for res in config_blocks.into_iter().map(read_rom).take(1) {
        let (block, buf) = res?;
        let cs_instructions = cs.disasm_all(&buf, block.vaddr as u64)?;
        let num_insn = cs_instructions.len();

        println!("Found {} instructions in block '{}'", num_insn, &block.name);

        let test = cs_instructions
            .iter()
            .take(100)
            .inspect(|i| println!("{}", i))
            .map(|i| {
                let detail = cs.insn_detail(&i)?;
                Instruction::from_components(&i, &detail)
            })
            .scan(NLState::Clear, |s, res| {
                Some(res.map(|i| indicate_newlines(s, i)))
            })
            .enumerate()
            .try_fold(FoldInsnState::with_cap(num_insn), fold_instructions)?;

        println!("");
        println!("Found linked values:");
        for link in test.links.iter() {
            println!("{:4}{}", "", link);
        }
        println!("");
        println!("{:?}", &test);
    }

    Ok(())
}

#[derive(Debug)]
struct FoldInsnState {
    instructions: Vec<Instruction>,
    registers: HashMap<RegId, LuiState>,
    links: Vec<LuiResolve>,
}

impl FoldInsnState {
    fn with_cap(insn_size: usize) -> Self {
        Self {
            instructions: Vec::with_capacity(insn_size),
            registers: HashMap::with_capacity(32),
            links: Vec::new(),
        }
    }
}

fn fold_instructions(
    mut state: FoldInsnState,
    (offset, insn): (usize, Result<Instruction, Pass1Error>),
) -> Result<FoldInsnState, Pass1Error> {
    let insn = insn?;

    if let Some(linked_values) = link_instructions(&mut state.registers, &insn, offset)? {
        state.links.extend(linked_values);
    }

    state.instructions.push(insn);

    Ok(state)
}

struct Block {
    instructions: Vec<Instruction>,
    locals: HashMap<u32, Label>,
    globals: HashMap<u32, Label>,
    externals: HashMap<u32, Label>,
}

#[derive(Debug, Copy, Clone)]
enum LuiState {
    Upper(RegId, i16, usize),
    Loaded(RegId, u32),
}

#[derive(Debug, Copy, Clone)]
struct LinkedVal {
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
enum LuiResolve {
    Pointer(LinkedVal),
    Immediate(LinkedVal),
    Float(LinkedVal),
}

impl fmt::Display for LuiResolve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
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

fn link_instructions<'s, 'i>(
    reg_state: &'s mut HashMap<RegId, LuiState>,
    insn: &'i Instruction,
    offset: usize,
) -> Result<Option<impl Iterator<Item = LuiResolve>>, Pass1Error> {
    use std::iter::once;
    use LuiResolve::*;
    use LuiState::*;
    use Pass1Error::*;

    // reset register state on subroutine exit
    if insn.jump.is_jrra() {
        reg_state.clear();
        return Ok(None);
    }

    // otherwise, look for specific instructions that typically indicate pointer or float loads
    let op = insn.id.0;
    match op {
        // Every immediate greater than 16bit in MIPS typically uses this instruction
        // to set the upper 16 bits. So, this has to set the upper bits of a register that
        // will be used in a later instruction as a pointer or float
        INS_LUI => {
            let reg = get_reg_n(&insn.operands, 0)
                .ok_or_else(|| MalformedLUI(insn.clone(), "register"))?;
            let imm =
                get_imm(&insn.operands).ok_or_else(|| MalformedLUI(insn.clone(), "immediate"))?;
            reg_state.insert(reg, Upper(reg, imm, offset));
            Ok(None)
        }
        // The `addiu` instruction is emitted with a matched `lui` for pointers.
        // The immediate value can be positive or negative
        INS_ADDIU => {
            let (dst, src, imm) = get_dsimm_tripple(&insn)?;
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
                    let lui_insn = LinkedVal::new(ptr, None, prior);
                    let lower_insn = LinkedVal::new(ptr, None, offset);

                    Some(once(Pointer(lui_insn)).chain(once(Pointer(lower_insn))))
                }))
        }
        // The `ori` instruction is emitted with a matched `lui` for large immediate values
        INS_ORI => {
            let (dst, src, imm) = get_dsimm_tripple(&insn)?;
            if dst != src {
                return Ok(None);
            }

            let output = reg_state
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
                    let lui_insn = LinkedVal::new(val, None, prior);
                    let lower_insn = LinkedVal::new(val, None, offset);

                    Some(once(Immediate(lui_insn)).chain(once(Immediate(lower_insn))))
                });

            Ok(output)
        }
        INS_MTC1 => unimplemented!(),
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
fn get_dsimm_tripple(insn: &Instruction) -> Result<(RegId, RegId, i16), Pass1Error> {
    use Pass1Error::*;

    let dst = get_reg_n(&insn.operands, 0)
        .ok_or_else(|| MissingInsnComponent(insn.clone(), "dst reg"))?;
    let src = get_reg_n(&insn.operands, 1)
        .ok_or_else(|| MissingInsnComponent(insn.clone(), "src reg"))?;
    let imm =
        get_imm(&insn.operands).ok_or_else(|| MissingInsnComponent(insn.clone(), "immediate"))?;

    Ok((dst, src, imm))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum NLState {
    Clear,
    Delay,
    NewLine,
}

// shouldn't have a jump in the delay slot of a jump, as that is undefined in MIPS.
// So, there's no worry about overlapping jump/branches... right?
fn indicate_newlines(state: &mut NLState, mut insn: Instruction) -> Instruction {
    use NLState::*;

    insn.new_line = *state == NewLine;

    *state = match state {
        Delay => NewLine,
        Clear | NewLine => match insn.jump {
            JumpKind::Jump(_) => Delay,
            JumpKind::JumpRegister(_) if insn.jump.is_jrra() => Delay,
            _ => Clear,
        },
    };

    insn
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum JumpKind {
    None,
    Branch(u32),
    BAL(u32),
    Jump(u32),
    JAL(u32),
    JumpRegister(RegId),
}

impl JumpKind {
    fn is_jrra(&self) -> bool {
        use capstone::arch::mips::MipsReg::MIPS_REG_RA;

        match self {
            Self::JumpRegister(r) => r.0 as u32 == MIPS_REG_RA,
            _ => false,
        }
    }
}

impl From<(&Insn<'_>, &InsnDetail<'_>)> for JumpKind {
    fn from((insn, details): (&Insn, &InsnDetail)) -> Self {
        use capstone::arch::mips::MipsInsnGroup::*;

        if !details.groups().any(|g| g.0 as u32 == MIPS_GRP_JUMP) {
            return Self::None;
        }

        let imm = details
            .arch_detail()
            .mips()
            .expect("All decompiled instructions should be MIPS")
            .operands()
            .find_map(|op| match op {
                MipsOperand::Imm(val) => Some(val as u32),
                _ => None,
            });

        let reg = details
            .arch_detail()
            .mips()
            .expect("All decompiled instructions should be MIPS")
            .operands()
            .find_map(|op| match op {
                MipsOperand::Reg(r) => Some(r),
                _ => None,
            });

        if let Some(imm) = imm {
            match insn.id().0 {
                INS_J => JumpKind::Jump(imm),
                INS_JAL => JumpKind::JAL(imm),
                INS_BAL => JumpKind::BAL(imm),
                _ => JumpKind::Branch(imm),
            }
        } else if let Some(jr_target) = reg {
            // catch `jr XX` and `jalr XX`
            JumpKind::JumpRegister(jr_target)
        } else {
            unreachable!("Not all branch/jump types covered?");
        }
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    id: capstone::InsnId,
    vaddr: u32,
    raw: u32,
    // same size as an `(A)Rc<str>` on 64bit, but no indirection/thread issues
    mnemonic: ArrayString<[u8; 16]>,
    op_str: Option<String>,
    operands: Vec<MipsOperand>,
    new_line: bool,
    jump: JumpKind,
    //linked_insn: usize,
}

impl Instruction {
    fn from_components(insn: &Insn, detail: &InsnDetail) -> Result<Self, Pass1Error> {
        use Pass1Error::{IllegalInsn, LongMnem};

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
        })
    }
}
