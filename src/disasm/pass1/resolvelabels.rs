//! Label/Symbol Name Resolution Overview
//! 1) Collect internal symbols from all blocks into two hashmaps:
//!       Global: addr => Label
//!       Overlays: Overlay => addr => Label
//!    This is done in `add_internal_labels_to_set` by combining the labels
//!    discovered by the disassembly with the labels provided by the user in the config.
//!    Also, add the overlay name to any found symbols
//! 2) Collect external symbols into three bins based on the symbol's address:
//!     i) Not Found symbols
//!     ii) Symbols that could be in multiple memory blocks
//!     iii) Symbols that could only be in a single block
//!    Put the the III symbols into their proper label maps
//! 3) Check the address of the possible multiple memory block symbols to see
//!    if there is already a matching symbol in one of the memory blocks. If so,
//!    remove that symbol from the bin
//! 4) Combine all not found/not in memory block symbols into one map
//! 5) Return a `Vec` of instructions and unresolved, multi-block symbols and
//!    the Not Found symbol map

use crate::disasm::{
    instruction::Instruction,
    labels::{Label, LabelSet},
    memmap::{AddrLocation, BlockName, CodeBlock, MemoryMap},
    pass1::findlabels::ConfigLabelLoc,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ResolvedBlock<'c> {
    pub instructions: Vec<Instruction>,
    pub label_loc_cache: HashMap<u32, LabelPlace>,
    pub multi_block_labels: Option<Vec<Label>>,
    pub info: &'c CodeBlock,
}

impl<'c> ResolvedBlock<'c> {
    fn from_processed(block: ProcessedBlock<'c>) -> (Self, Option<Vec<Label>>) {
        let (multi_block_labels, not_found) = block.unresolved.into_components();

        (
            Self {
                instructions: block.instructions,
                label_loc_cache: block.label_loc_cache,
                multi_block_labels,
                info: block.info,
            },
            not_found,
        )
    }
}

pub type NotFoundLabels = HashMap<u32, Label>;

#[derive(Debug, Clone)]
pub enum LabelPlace {
    Internal,
    Global,
    NotFound,
    MultipleExtern,
    External(BlockName),
}

pub fn resolve<'c>(
    label_set: &mut LabelSet,
    memory_map: &MemoryMap,
    blocks: Vec<LabeledBlock<'c>>,
) -> (Vec<ResolvedBlock<'c>>, NotFoundLabels) {
    let n = blocks.len();
    let ext_only_blocks = add_internal_labels_to_set(label_set, blocks);
    let pass1_ext_blocks = pass1_external_labels(label_set, memory_map, ext_only_blocks);

    let output_acc = (Vec::with_capacity(n), NotFoundLabels::new());
    pass1_ext_blocks
        .into_iter()
        .fold(output_acc, |mut acc, mut block| {
            pass2_multi_labels(&mut block, label_set);

            let (resolved_block, not_found) = ResolvedBlock::from_processed(block);

            if let Some(labels) = not_found {
                acc.1.extend(labels.into_iter().map(|l| (l.addr, l)));
            };

            acc.0.push(resolved_block);

            acc
        })
}

pub struct LabeledBlock<'c> {
    pub instructions: Vec<Instruction>,
    pub info: &'c CodeBlock,
    pub internal_labels: HashMap<u32, Label>,
    pub external_labels: HashMap<u32, Label>,
    pub config_labels: HashMap<u32, ConfigLabelLoc>,
}

impl<'c> LabeledBlock<'c> {
    fn into_extern_labeled(self) -> (ExternLabeledBlock<'c>, HashMap<u32, Label>) {
        let Self {
            instructions,
            info,
            internal_labels,
            external_labels,
            config_labels,
        } = self;
        let n = internal_labels.len() + external_labels.len() + config_labels.len();
        let config_iter = config_labels
            .into_iter()
            .map(|(addr, loc)| (addr, match loc {
                ConfigLabelLoc::Internal => LabelPlace::Internal,
                ConfigLabelLoc::Global => LabelPlace::Global,
            }));

        let label_loc_cache =
            internal_labels
                .keys()
                .copied()
                .map(|addr| (addr, LabelPlace::Internal))
                .chain(config_iter)
                .fold(HashMap::with_capacity(n), |mut map, l| {
                    map.insert(l.0, l.1);
                    map
                });

        (
            ExternLabeledBlock {
                instructions,
                info,
                external_labels,
                label_loc_cache,
            },
            internal_labels,
        )
    }
}

struct ExternLabeledBlock<'c> {
    instructions: Vec<Instruction>,
    info: &'c CodeBlock,
    label_loc_cache: HashMap<u32, LabelPlace>,
    external_labels: HashMap<u32, Label>,
}

impl<'c> ExternLabeledBlock<'c> {
    fn into_proc_block(self) -> (ProcessedBlock<'c>, HashMap<u32, Label>) {
        let Self {
            instructions,
            info,
            external_labels,
            label_loc_cache,
        } = self;
        (
            ProcessedBlock {
                instructions,
                info,
                label_loc_cache,
                unresolved: UnresolvedBlockLabels::new(),
            },
            external_labels,
        )
    }
}

struct ProcessedBlock<'c> {
    instructions: Vec<Instruction>,
    info: &'c CodeBlock,
    label_loc_cache: HashMap<u32, LabelPlace>,
    unresolved: UnresolvedBlockLabels,
}

/// Hold any `Label`s that couldn't be found or resolved into a single overlay.
/// The label originates from `block`
#[derive(Debug)]
struct UnresolvedBlockLabels {
    multiple: Option<Vec<Label>>,
    not_found: Option<Vec<Label>>,
}

impl<'c> UnresolvedBlockLabels {
    fn new() -> Self {
        Self {
            multiple: None,
            not_found: None,
        }
    }

    fn into_components(self) -> (Option<Vec<Label>>, Option<Vec<Label>>) {
        (self.multiple, self.not_found)
    }
}

fn add_internal_labels_to_set<'c>(
    label_set: &mut LabelSet,
    blocks: Vec<LabeledBlock<'c>>,
) -> Vec<ExternLabeledBlock<'c>> {
    let fold_into_externblock =
        |mut acc: Vec<ExternLabeledBlock<'c>>,
         (extrn_block, internal_labels): (ExternLabeledBlock<'c>, HashMap<u32, Label>)| {
            let block_name = &extrn_block.info.name;

            // All internal `Label`s have their block name set; this only
            // needs to be changed for the global labels:
            //  to `global` from the specific global code block name
            if let Some(ovl_labels) = label_set.overlays.get_mut(block_name) {
                ovl_labels.extend(internal_labels);
            } else {
                let adj_label_iter = internal_labels.into_iter().map(|(addr, mut label)| {
                    label.set_global();
                    (addr, label)
                });

                label_set.globals.extend(adj_label_iter);
            }

            acc.push(extrn_block);

            acc
        };

    let output = Vec::with_capacity(blocks.len());
    blocks
        .into_iter()
        .map(LabeledBlock::into_extern_labeled)
        .fold(output, fold_into_externblock)
}

/// Attempt to resolve the location of external labels from a block of `blocks`
/// based on the address of that label, and that block's memory map
fn pass1_external_labels<'c>(
    label_set: &mut LabelSet,
    memory_map: &MemoryMap,
    blocks: Vec<ExternLabeledBlock<'c>>,
) -> Vec<ProcessedBlock<'c>> {
    use AddrLocation::*;

    let mut output = Vec::with_capacity(blocks.len());

    for block in blocks {
        let (mut proc_block, external_labels) = block.into_proc_block();
        let block_name = &proc_block.info.name;

        println!("First pass on external labels for {}", &block_name);
        println!(
            "{:4}Started with {} external labels",
            "",
            &external_labels.len()
        );
        for (addr, mut label) in external_labels {
            match memory_map.get_addr_location(addr, block_name) {
                NotFound => {
                    println!("{:8}Couldn't find label in memory: {:x?}", "", &label);
                    proc_block
                        .label_loc_cache
                        .insert(addr, LabelPlace::NotFound);
                    label.set_not_found();
                    proc_block
                        .unresolved
                        .not_found
                        .get_or_insert_with(Vec::new)
                        .push(label);
                }
                Multiple(hits) => {
                    label.set_unresolved(hits);
                    proc_block
                        .unresolved
                        .multiple
                        .get_or_insert_with(Vec::new)
                        .push(label);
                }
                Single(block) => {
                    if let Some(ovl_labels) = label_set.overlays.get_mut(&block) {
                        println!(
                            "{:8}Found single label from '{}' into '{}': {:x?}",
                            "", &block_name, &block, &label
                        );
                        proc_block
                            .label_loc_cache
                            .insert(addr, LabelPlace::External(block.clone()));
                        ovl_labels.entry(addr).or_insert_with(|| {
                            println!("{:10}Label not found; inserted!", "");
                            label.set_overlay(&block);
                            label
                        });
                    } else {
                        // must be a label from a global symbol
                        println!(
                            "{:8}Found global label from '{}' into '{}': {:x?}",
                            "", &block_name, &block, &label
                        );
                        proc_block.label_loc_cache.insert(addr, LabelPlace::Global);
                        label_set.globals.entry(addr).or_insert_with(|| {
                            println!("{:10}Global label not found; inserted!", "");
                            label.set_global();
                            label
                        });
                    }
                }
            }
        }
        let unres = proc_block
            .unresolved
            .multiple
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0);
        let notfound = proc_block
            .unresolved
            .not_found
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0);
        println!(
            "{:4}Ended with {} unresovled labels and {} not found labels",
            "", unres, notfound
        );

        output.push(proc_block);
    }

    output
}

fn pass2_multi_labels(block: &mut ProcessedBlock, label_set: &mut LabelSet) {
    // check the blocks that the label could be in (based on address only)
    // to see if there is already a known label
    let find_label_already_in_blocks = |label: Label| {
        let found_label_in = label
            .get_possible_blocks()
            .expect("only called on a label with multiple possible block locations")
            .iter()
            .filter(|name| {
                label_set
                    .overlays
                    .get(*name)
                    .and_then(|lbs| lbs.get(&label.addr))
                    .map(|found_label| label.kind == found_label.kind || found_label.is_named())
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<BlockName>>();
        (label, found_label_in)
    };

    // Generate a new `Vec` of possible locations for `label`, if the label
    // was found to already be in other locations by `find_label_already_in_blocks`
    let cache = &mut block.label_loc_cache;
    let fold_new_multilabels =
        |mut acc: Vec<Label>, (mut label, found_in): (Label, Vec<BlockName>)| {
            println!(
                "{:4}Found label {:08x} <{:?}> in {:x?}",
                "", label.addr, label.kind, &found_in
            );
            println!("{:8}Used to be in {:x?}", "", &label.location);

            let addr = label.addr;
            match found_in.len() {
                // `label` was not in any other blocks, so can't reduce possibilities
                // The label already is tied to the `Vec` of possible blocks, so
                // just put the label back into the unresolved pile
                0 => {
                    cache.insert(addr, LabelPlace::MultipleExtern);
                    acc.push(label);
                }
                // `label` (address and type) is present in exactly one other block.
                // Nothing to do with the label, but update the label's location in the cache
                1 => {
                    let loc = found_in[0].clone();
                    cache.insert(addr, LabelPlace::External(loc));
                }
                // A matching `Label` was found in >1 other blocks. Reduce the possibilites
                // for this label
                _ => {
                    cache.insert(addr, LabelPlace::MultipleExtern);
                    label.set_multiple(found_in);
                    acc.push(label);
                }
            }

            acc
        };

    if let Some(multiple) = block.unresolved.multiple.take() {
        let max = multiple.len();

        println!(
            "Second pass on multi-block labels from {}",
            &block.info.name
        );
        let fitlered_mutliple = multiple
            .into_iter()
            .map(find_label_already_in_blocks)
            .fold(Vec::with_capacity(max), fold_new_multilabels);

        block.unresolved.multiple.replace(fitlered_mutliple);
    }
}
