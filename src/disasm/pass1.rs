mod jumps;
mod labeling;
mod linkinsn;

use crate::config::Config;
use crate::disasm::{
    instruction::{InsnParseErr, Instruction},
    mipsvals::*,
    CodeBlock, Label,
};
use capstone::{arch::mips::MipsOperand, arch::mips::MipsReg::*, prelude::*};
use err_derive::Error;
use linkinsn::{link_instructions, LinkInsnErr, LinkState};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use labeling::LabelState;

pub use jumps::JumpKind;
pub use linkinsn::{Link, LinkedVal};

#[derive(Debug, Error)]
pub enum Pass1Error {
    #[error(display = "Problem when attempting to combine constants")]
    LinkInsn(#[error(source)] LinkInsnErr),
    #[error(display = "Problem parsing capstone instruction")]
    InsnParse(#[error(source)] InsnParseErr),
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
            .take(2000)
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
    (offset, insn): (usize, Result<Instruction, InsnParseErr>),
) -> Result<FoldInsnState, Pass1Error> {
    let mut insn = insn?;
    let maybe_linked = link_instructions(&mut state.link_state, &insn, offset)?;

    fix_move(&mut insn);
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
        .expect("Insn Vec should have >0 isns");
    state.label_state.check_instruction(insn_ref);

    Ok(state)
}

/// capstone `move d, s` instructions should be either an `or d, s, $zero`
/// or an `addu d, s, $zero`. This converts the `Instruction` back
fn fix_move(insn: &mut Instruction) {
    // MIPS `or` insn:       0000 00ss ssst tttt dddd d000 0010 0101  => 37
    // MIPS 'addu' insn:     0000 00ss ssst tttt dddd d000 0010 0001  => 33
    const INSN_MASK: u32 = 0b1111_1100_0000_0000_0000_0111_1111_1111;

    if insn.id.0 != INS_MOVE {
        return;
    }

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
