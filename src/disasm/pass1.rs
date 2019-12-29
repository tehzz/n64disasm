mod findlabels;
mod jumps;
mod linkinsn;
mod resolvelabels;

use crate::config::Config;
use crate::disasm::{
    csutil,
    instruction::{InsnParseErr, Instruction},
    memmap::{CodeBlock, MemoryMap, BlockName},
    LabelSet, Label,
};
use capstone::prelude::*;
use err_derive::Error;
use linkinsn::{link_instructions, LinkInsnErr, LinkState};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::collections::HashMap;
use log::{info, debug};

use findlabels::LabelState;
use resolvelabels::LabeledBlock;

pub use jumps::JumpKind;
pub use linkinsn::{Link, LinkedVal};
pub use resolvelabels::{ResolvedBlock, LabelPlace};

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

type P1Result<T> = Result<T, Pass1Error>;

pub struct Pass1 {
    memory_map: MemoryMap,
    labels: LabelSet,
    blocks: Vec<BlockInsn>,
    not_found_labels: HashMap<u32, Label>,
}

struct BlockInsn {
    instructions: Vec<Instruction>,
    name: BlockName,
    /// Labels that could be in multiple other blocks
    unresolved_labels: Option<HashMap<u32, Label>>,
    /// Map of address to where the label for the address is
    label_locations: HashMap<u32, LabelPlace>,
}

impl From<ResolvedBlock<'_>> for BlockInsn {
    fn from(src: ResolvedBlock) -> Self {
        let unresolved_labels = src.multi_block_labels.map(|v| v.into_iter().map(|l| (l.addr, l)).collect());
        let name = src.info.name.clone();

        Self {
            instructions: src.instructions,
            name,
            unresolved_labels,
            label_locations: src.label_loc_cache,
        }
    }
}

pub fn pass1(config: Config, rom: &Path) -> P1Result<Pass1> {
    let Config {
        memory: memory_map,
        labels: mut config_labels,
    } = config;
    let cs = csutil::get_instance()?;

    let mut rom = File::open(rom)?;
    let read_rom = |block| read_codeblock(block, &mut rom);
    let proc_insns = |res| process_block(res, &config_labels, &cs);

    let labeled_blocks = memory_map
        .blocks
        .iter()
        .map(read_rom)
        .map(proc_insns)
        .collect::<P1Result<Vec<_>>>()?;

    let (blocks, not_found_labels) = resolvelabels::resolve(&mut config_labels, &memory_map, labeled_blocks);
    let instructions = blocks.into_iter().map(BlockInsn::from).collect();
    let pass1 = Pass1 {
        memory_map,
        labels: config_labels,
        blocks: instructions,
        not_found_labels
    };

    Ok(pass1)
}

/// Helper function to read a `CodeBlock`'s raw bytes from the ROM
fn read_codeblock<'a>(
    block: &'a CodeBlock,
    rom: &mut File,
) -> io::Result<(&'a CodeBlock, Vec<u8>)> {
    let (start, size) = block.range.get_rom_offsets();
    let mut buf = vec![0u8; size];

    rom.seek(SeekFrom::Start(start))?;
    rom.read_exact(&mut buf)?;

    Ok((block, buf))
}

fn process_block<'b>(
    res: io::Result<(&'b CodeBlock, Vec<u8>)>,
    labels: &'_ LabelSet,
    cs: &'_ Capstone,
) -> P1Result<LabeledBlock<'b>> {
    let (block, buf) = res?;
    let block_vaddr = block.range.get_text_vaddr() as u64;
    let cs_instructions = cs.disasm_all(&buf, block_vaddr)?;
    let num_insn = cs_instructions.len();

    info!("Found {} instructions in block '{}'", num_insn, &block.name);

    let label_state = LabelState::from_config(&block.range, &labels, &block.name);
    let pass1_state = FoldInsnState::new(num_insn, label_state);

    let FoldInsnState {
        instructions,
        label_state,
        ..
    } = cs_instructions
        .iter()
        .map(|i| {
            let detail = cs.insn_detail(&i)?;
            Instruction::from_components(&i, &detail)
        })
        .scan(NLState::Clear, |s, res| {
            Some(res.map(|i| indicate_newlines(s, i)))
        })
        .enumerate()
        .try_fold(pass1_state, fold_instructions)?;

    let LabelState {
        internals: internal_labels,
        externals: external_labels,
        ..
    } = label_state;

    Ok(LabeledBlock {
        instructions,
        info: block,
        internal_labels,
        external_labels,
    })
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
) -> P1Result<FoldInsnState> {
    let mut insn = insn?;
    let maybe_linked = link_instructions(&mut state.link_state, &insn, offset)?;

    csutil::correct_insn(&mut insn);
    state.instructions.push(insn);

    if let Some(linked_values) = maybe_linked {
        for link in linked_values.filter(|l| !l.is_empty()) {
            let Link { instruction, .. } = link.get_link().expect("no empty linked values");

            debug!(
                "{:4}@{:>5}: {}",
                "",
                instruction as isize - offset as isize,
                &link
            );

            state.instructions[instruction].linked = link;
        }
    }

    // store any labels that were generated by this newly inserted instruction
    let insn_ref = state
        .instructions
        .last()
        .expect("Insn Vec should have >0 isns");
    state.label_state.check_instruction(insn_ref);

    Ok(state)
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
