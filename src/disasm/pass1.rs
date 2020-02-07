mod findfiles;
mod findlabels;
mod findsections;
mod jumps;
mod linkinsn;
mod resolvelabels;
mod routinenl;

use crate::config::Config;
use crate::disasm::{
    csutil,
    instruction::{InsnParseErr, Instruction},
    labels::{Label, LabelSet},
    memmap::{BlockName, CodeBlock, MemoryMap},
};
use capstone::prelude::*;
use err_derive::Error;
use linkinsn::{link_instructions, LinkInsnErr, LinkState};
use log::info;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use findfiles::FindFileState;
use findlabels::LabelState;
use findsections::FindSectionState;
use resolvelabels::LabeledBlock;
use routinenl::NLState;

pub use findfiles::FileBreak;
pub use jumps::JumpKind;
pub use linkinsn::{Link, LinkedVal};
pub use resolvelabels::{LabelPlace, ResolvedBlock};

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
    pub memory_map: MemoryMap,
    pub labels: LabelSet,
    pub blocks: Vec<BlockInsn>,
    pub not_found_labels: HashMap<u32, Label>,
}

pub struct BlockInsn {
    pub instructions: Vec<Instruction>,
    pub name: BlockName,
    /// Labels that could be in multiple other blocks
    pub unresolved_labels: Option<HashMap<u32, Label>>,
    /// Map of address to where the label for the address is
    pub label_locations: HashMap<u32, LabelPlace>,
}

impl From<ResolvedBlock<'_>> for BlockInsn {
    fn from(src: ResolvedBlock) -> Self {
        let unresolved_labels = src
            .multi_block_labels
            .map(|v| v.into_iter().map(|l| (l.addr, l)).collect());
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

    let (resolved, not_found_labels) =
        resolvelabels::resolve(&mut config_labels, &memory_map, labeled_blocks);
    let blocks = resolved.into_iter().map(BlockInsn::from).collect();

    let pass1 = Pass1 {
        memory_map,
        labels: config_labels,
        blocks,
        not_found_labels,
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
    let section_state = FindSectionState::new(&block);
    let pass1_state = FoldInsnState::new(num_insn, label_state, section_state);

    let processed = cs_instructions
        .iter()
        .map(|i| {
            let detail = cs.insn_detail(&i)?;
            Instruction::from_components(&i, &detail)
        })
        .enumerate()
        .try_fold(pass1_state, fold_instructions)?;

    let FoldInsnState {
        instructions,
        label_state,
        section_state,
        ..
    } = processed;

    let LabelState {
        internals: internal_labels,
        externals: external_labels,
        config_labels,
        ..
    } = label_state;

    let sections = section_state.finish(&instructions);

    println!("Found sections in {}", &block.name);
    for section in sections {
        println!("{:2}{:x?}", "", &section);
    }

    Ok(LabeledBlock {
        instructions,
        info: block,
        internal_labels,
        external_labels,
        config_labels,
    })
}

#[derive(Debug)]
struct FoldInsnState<'c> {
    instructions: Vec<Instruction>,
    link_state: LinkState,
    label_state: LabelState<'c>,
    section_state: FindSectionState<'c>,
    nl_state: NLState,
    file_state: FindFileState,
}

impl<'c> FoldInsnState<'c> {
    fn new(insn_size: usize, labels: LabelState<'c>, sections: FindSectionState<'c>) -> Self {
        Self {
            instructions: Vec::with_capacity(insn_size),
            link_state: LinkState::new(),
            label_state: labels,
            section_state: sections,
            nl_state: NLState::default(),
            file_state: FindFileState::default(),
        }
    }
}

fn fold_instructions(
    mut state: FoldInsnState,
    (offset, insn): (usize, Result<Instruction, InsnParseErr>),
) -> P1Result<FoldInsnState> {
    let mut insn = insn?;
    csutil::correct_insn(&mut insn);
    state.nl_state.newline_between_routines(&mut insn);
    state.file_state.find_file_gaps(&mut insn);

    // link any symbols in this instruction with prior instructions
    // this also stores the instruction into the fold state instruction Vec
    let insn_ref = link_instructions(&mut state.link_state, insn, offset, &mut state.instructions)?;

    // store any labels that were generated by this newly inserted instruction
    state.label_state.check_instruction(insn_ref);
    state.section_state.check_insn(insn_ref);

    Ok(state)
}
