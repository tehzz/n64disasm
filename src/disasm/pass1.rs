mod findfiles;
mod findlabels;
mod findsections;
mod jumps;
mod linkinsn;
mod parsedata;
mod resolvelabels;
mod routinenl;

use crate::config::Config;
use crate::disasm::{
    csutil,
    instruction::{InsnParseErr, Instruction},
    labels::{Label, LabelSet},
    memmap::{BlockName, CodeBlock, MemoryMap},
};
use err_derive::Error;
use linkinsn::{link_instructions, LinkInsnErr, LinkState};
use log::info;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};

use findfiles::FindFileState;
use findlabels::LabelState;
use findsections::FindSectionState;
use resolvelabels::LabeledBlock;
use routinenl::NLState;

pub use findfiles::FileBreak;
pub use findsections::{BlockLoadedSections, LoadSectionInfo};
pub use jumps::JumpKind;
pub use linkinsn::{Link, LinkedVal};
pub use parsedata::{DataEntry, ParsedData};
pub use resolvelabels::{LabelPlace, ResolveLabelsErr, ResolvedBlock};

#[derive(Debug, Error)]
pub enum Pass1Error {
    #[error(display = "Problem when attempting to combine constants")]
    LinkInsn(#[error(source)] LinkInsnErr),
    #[error(display = "Problem parsing capstone instruction")]
    InsnParse(#[error(source)] InsnParseErr),
    #[error(display = "Problem resolving the location of labels")]
    LabelRes(#[error(source)] ResolveLabelsErr),
    #[error(display = "Problem with capstone disassembly")]
    Capstone(#[error(source)] capstone::Error),
}

type P1Result<T> = Result<T, Pass1Error>;

pub struct Pass1<'rom> {
    pub memory_map: MemoryMap,
    pub labels: LabelSet,
    pub blocks: Vec<BlockInsn<'rom>>,
    pub not_found_labels: HashMap<u32, Label>,
}

pub struct BlockInsn<'rom> {
    pub instructions: Vec<Instruction>,
    pub name: BlockName,
    /// Sections that are loaded from ROM (.text and .data) for this block
    pub loaded_sections: BlockLoadedSections,
    /// Parsed data from this block's .data section
    pub parsed_data: BTreeMap<u32, DataEntry<'rom>>,
    /// Labels that could be in multiple other blocks
    pub unresolved_labels: Option<HashMap<u32, Label>>,
    /// Map of address to where the label for the address is
    pub label_locations: HashMap<u32, LabelPlace>,
}

impl<'rom> From<ResolvedBlock<'_, 'rom>> for BlockInsn<'rom> {
    fn from(src: ResolvedBlock<'_, 'rom>) -> Self {
        let unresolved_labels = src
            .multi_block_labels
            .map(|v| v.into_iter().map(|l| (l.addr, l)).collect());
        let name = src.info.name.clone();

        Self {
            instructions: src.instructions,
            name,
            loaded_sections: src.loaded_sections,
            parsed_data: src.parsed_data,
            unresolved_labels,
            label_locations: src.label_loc_cache,
        }
    }
}

pub fn pass1(config: Config, rom: &[u8]) -> P1Result<Pass1> {
    let Config {
        memory: memory_map,
        labels: mut existing_labels,
        expak,
    } = config;

    let read_rom = |block| read_codeblock(block, &rom);
    let proc_insns = |res| process_block(res, &existing_labels, expak);

    let labeled_blocks = memory_map
        .blocks
        .par_iter()
        .map(read_rom)
        .map(proc_insns)
        .collect::<P1Result<Vec<_>>>()?;

    let (checked_blocks, not_found_labels) =
        resolvelabels::resolve(&mut existing_labels, &memory_map, labeled_blocks)?;
    let blocks = checked_blocks.into_iter().map(BlockInsn::from).collect();

    let pass1 = Pass1 {
        memory_map,
        labels: existing_labels,
        blocks,
        not_found_labels,
    };

    Ok(pass1)
}

/// Helper function to read a `CodeBlock`'s raw bytes from the ROM
fn read_codeblock<'a, 'b>(block: &'a CodeBlock, rom: &'b [u8]) -> (&'a CodeBlock, &'b [u8]) {
    let (start, end) = block.range.get_rom_offsets();
    let block_data = &rom[start..end];

    (block, block_data)
}

fn process_block<'a, 'rom>(
    (block, buf): (&'a CodeBlock, &'rom [u8]),
    labels: &'_ LabelSet,
    expak: bool,
) -> P1Result<LabeledBlock<'a, 'rom>> {
    let cs = csutil::get_instance()?;
    let block_vaddr = block.range.get_ram_start() as u64;
    let cs_instructions = cs.disasm_all(buf, block_vaddr)?;
    let num_insn = cs_instructions.len();

    info!("Found {} instructions in block '{}'", num_insn, &block.name);

    let label_state = LabelState::from_config(&block.range, &buf, &labels, &block.name);
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
        mut label_state,
        section_state,
        ..
    } = processed;

    let loaded_sections = section_state.finish(&instructions);
    info!(
        "Found .text/.data sections in {}\n{:x?}",
        &block.name, &loaded_sections
    );
    label_state.ensure_internal_label_section(&loaded_sections);
    label_state.find_and_add_data(&loaded_sections, expak);

    let LabelState {
        internals: internal_labels,
        externals: external_labels,
        existing_labels,
        data: parsed_data,
        ..
    } = label_state;

    Ok(LabeledBlock {
        instructions,
        info: block,
        loaded_sections,
        parsed_data,
        internal_labels,
        external_labels,
        existing_labels,
    })
}

#[derive(Debug)]
struct FoldInsnState<'a, 'rom> {
    instructions: Vec<Instruction>,
    link_state: LinkState,
    label_state: LabelState<'a, 'rom>,
    section_state: FindSectionState<'a>,
    nl_state: NLState,
    file_state: FindFileState,
}

impl<'a, 'rom> FoldInsnState<'a, 'rom> {
    fn new(insn_size: usize, labels: LabelState<'a, 'rom>, sections: FindSectionState<'a>) -> Self {
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

fn fold_instructions<'a, 'rom>(
    mut state: FoldInsnState<'a, 'rom>,
    (offset, insn): (usize, Result<Instruction, InsnParseErr>),
) -> P1Result<FoldInsnState<'a, 'rom>> {
    let mut insn = insn?;
    csutil::correct_insn(&mut insn);
    state.nl_state.newline_between_routines(&mut insn);
    state.file_state.find_file_gaps(&mut insn);

    // link any symbols in this instruction with prior instructions
    // this also stores the instruction into the fold state instruction Vec
    let insn_ref = link_instructions(&mut state.link_state, insn, offset, &mut state.instructions)?;

    // store any labels that were generated by this newly inserted instruction
    state.label_state.check_instruction(insn_ref);
    // use this instruction to find when the instruction stream switches
    // from real .text instructions to weird, not-correctly-parsed .data
    state.section_state.check_insn(insn_ref);

    Ok(state)
}
