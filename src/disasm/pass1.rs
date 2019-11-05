mod linkinsn;

use crate::config::Config;
use crate::disasm::{mipsinsn::*, CodeBlock, Label, LabelSet};
use arrayvec::ArrayString;
use capstone::{arch::mips::MipsOperand, arch::mips::MipsReg::*, prelude::*, Insn};
use err_derive::Error;
use linkinsn::{link_instructions, LinkInsnErr, LinkState};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

pub use linkinsn::{Link, LinkedVal};

#[derive(Debug, Error)]
pub enum Pass1Error {
    #[error(display = "Problem when attempting to combine constants")]
    LinkInsn(#[error(source)] LinkInsnErr),
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
        labels: config_labels,
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

    for res in config_blocks.into_iter().map(read_rom).take(5) {
        let (block, buf) = res?;
        let cs_instructions = cs.disasm_all(&buf, block.vaddr as u64)?;
        let num_insn = cs_instructions.len();

        println!("Found {} instructions in block '{}'", num_insn, &block.name);
        let block_size = block.rom_end - block.rom_start;
        let range = BlockRange::new(block.vaddr, block.vaddr + block_size);
        let label_state = LabelState::from_config(range, &config_labels, &block.name);

        let test = cs_instructions
            .iter()
            .take(150)
            .inspect(|i| println!("{}", i))
            .map(|i| {
                let detail = cs.insn_detail(&i)?;
                Instruction::from_components(&i, &detail)
            })
            .scan(NLState::Clear, |s, res| {
                Some(res.map(|i| indicate_newlines(s, i)))
            })
            .enumerate()
            .try_fold(FoldInsnState::new(num_insn, label_state), fold_instructions)?;

        println!("");
        println!("internal:\n{:#x?}", &test.label_state.internals);
        println!("external:\n{:#x?}", &test.label_state.externals);
    }

    Ok(())
}

/*
enum Section {
    Bss,
    Text,
    Data,
}
*/

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct BlockRange {
    start: u32,
    end: u32,
}

impl BlockRange {
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    fn contains(&self, addr: u32) -> bool {
        self.start <= addr && addr < self.end
    }
}

#[derive(Debug)]
struct LabelState<'c> {
    range: BlockRange,
    config_global: &'c HashMap<u32, Label>,
    config_ovl: Option<&'c HashMap<u32, Label>>,
    internals: HashMap<u32, Label>,
    externals: HashMap<u32, Label>, // subroutines or data that are not in the current block
}

impl<'c> LabelState<'c> {
    fn from_config(range: BlockRange, set: &'c LabelSet, name: &'_ str) -> Self {
        Self {
            range,
            config_global: &set.globals,
            config_ovl: set.overlays.get(name),
            internals: HashMap::new(),
            externals: HashMap::new(),
        }
    }

    /// extract a (possible) label from an instruction. This doesn't deal with
    /// assigning an overlay to a label
    /// Branch => local label
    /// J => internal or external subroutine
    /// Linked (Not float) => data label
    fn check_instruction(&mut self, insn: &Instruction) {
        use JumpKind::*;

        match insn.jump {
            Branch(addr) | BAL(addr) => self.insert_local(addr),
            Jump(addr) | JAL(addr) => self.insert_subroutine(addr),
            _ => (),
        };
    }

    /// check if a given addr is contained within this state's memory range
    fn is_in_config(&self, addr: u32) -> bool {
        self.config_global.contains_key(&addr)
            || self
                .config_ovl
                .map(|s| s.contains_key(&addr))
                .unwrap_or(false)
    }

    /// check if a given addr is contained within this state's memory range
    fn is_internal(&self, addr: u32) -> bool {
        self.range.contains(addr)
    }

    fn insert_local(&mut self, addr: u32) {
        if self.is_in_config(addr) {
            return;
        }

        if !self.internals.contains_key(&addr) {
            self.internals.insert(addr, Label::local(addr));
        }
    }
    fn insert_subroutine(&mut self, addr: u32) {
        if self.is_in_config(addr) {
            return;
        }

        if self.is_internal(addr) {
            if !self.internals.contains_key(&addr) {
                self.internals.insert(addr, Label::global(addr));
            }
        } else if !self.externals.contains_key(&addr) {
            self.externals.insert(addr, Label::global(addr));
        }
    }
    fn insert_data(&mut self, addr: u32) {
        if self.is_in_config(addr) {
            return;
        }

        if self.is_internal(addr) {
            if !self.internals.contains_key(&addr) {
                self.internals.insert(addr, Label::data(addr));
            }
        } else if !self.externals.contains_key(&addr) {
            self.externals.insert(addr, Label::data(addr));
        }
    }
}

#[derive(Debug)]
struct FoldInsnState<'c> {
    instructions: Vec<Instruction>,
    link_state: LinkState,
    label_state: LabelState<'c>,
}

impl<'c> FoldInsnState<'c> {
    fn new(insn_size: usize, labels: LabelState<'c>) -> Self {
        Self {
            instructions: Vec::with_capacity(insn_size),
            link_state: LinkState::new(),
            label_state: labels,
        }
    }
}

fn fold_instructions(
    mut state: FoldInsnState,
    (offset, insn): (usize, Result<Instruction, Pass1Error>),
) -> Result<FoldInsnState, Pass1Error> {
    let insn = insn?;
    let maybe_linked = link_instructions(&mut state.link_state, &insn, offset)?;

    // TODO: fix "move" instructions (id 423)
    state.instructions.push(insn);

    if let Some(linked_values) = maybe_linked {
        for link in linked_values.filter(|l| !l.is_empty()) {
            let Link { instruction, .. } = link.get_link().expect("no empty linked values");

            println!(
                "{:4}@{:>5}: {}",
                "",
                instruction as isize - offset as isize,
                &link
            );

            state.instructions[instruction].linked = link;
        }
    }

    // store any labels this instruction has generated
    let insn_ref = state
        .instructions
        .last()
        .expect("Insn Vec should have 1+ isns");
    state.label_state.check_instruction(insn_ref);

    Ok(state)
}

struct Block {
    instructions: Vec<Instruction>,
    locals: HashMap<u32, Label>,
    globals: HashMap<u32, Label>,
    externals: HashMap<u32, Label>,
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
        match self {
            Self::JumpRegister(r) => r.0 as u32 == MIPS_REG_RA,
            _ => false,
        }
    }
}

impl From<(&Insn<'_>, &InsnDetail<'_>)> for JumpKind {
    fn from((insn, details): (&Insn, &InsnDetail)) -> Self {
        use capstone::arch::mips::MipsInsnGroup::*;

        // for some reason, the MIPS `j`,`jal`, `jalr`, etc. instructions are not in the jump group...
        // in fact, they have no specific group of their own.
        if !details.groups().any(|g| g.0 as u32 == MIPS_GRP_JUMP)
            && insn.id().0 != INS_JAL
            && insn.id().0 != INS_J
        {
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
            // catch `jr XX` and `jalr XX`, but I don't think they make it here
            // do to the above noted issue with capstone
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
    linked: LinkedVal,
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
            linked: LinkedVal::Empty,
        })
    }
}
