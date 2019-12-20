//! Label/Symbol Name Resolution Overview
//! 1) Collect internal symbols from all blocks into two hashmaps:
//!       Global: addr => Label
//!       Overlays: Overlay => addr => Label
//!    This is done in `combine_internal_labels` by combining the labels
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
    memmap::{AddrLocation, BlockName, CodeBlock, MemoryMap},
    Label, LabelSet,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ResolvedBlock<'c> {
    instructions: Vec<Instruction>,
    multi_block_labels: Option<Vec<Label>>,
    name: &'c CodeBlock,
}

impl<'c> ResolvedBlock<'c> {
    fn new(block: ProcessedBlock<'c>, labels: Option<Vec<Label>>) -> Self {
        Self {
            instructions: block.instructions,
            multi_block_labels: labels,
            name: block.block,
        }
    }
}

pub type NotFoundLabelsMap = HashMap<u32, Label>;

pub fn resolve(label_set: &mut LabelSet, memory_map: &MemoryMap, blocks: Vec<LabeledBlock>) {
    let external_labeled_blocks = combine_internal_labels(label_set, blocks);
    let combined_externals =
        combine_unique_external_labels(label_set, memory_map, external_labeled_blocks);

    let mut notfound_map = NotFoundLabelsMap::new();
    for (block, mut unresolved_labels) in combined_externals {
        println!( "Unresolved multi-block labels in {}", unresolved_labels.block );
        unresolved_labels.resolve_multi_labels(label_set);
        let (multi_block_labels, not_found) = unresolved_labels.into_components();

        if let Some(labels) = not_found {
            notfound_map.extend(
                labels.into_iter()
                .map(|l| (l.addr, l))
            );
        }

        let resolved_block = ResolvedBlock::new(block, multi_block_labels);

        println!("{:4}{:#x?}", "",resolved_block.multi_block_labels);
    }

    println!("Not Found Labels:\n{:4}{:#x?}", "", notfound_map);
}

fn combine_unique_external_labels<'c>(
    label_set: &mut LabelSet,
    memory_map: &MemoryMap,
    blocks: Vec<ExternLabeledBlock<'c>>,
) -> Vec<(ProcessedBlock<'c>, UnresolvedBlockLabels<'c>)> {
    use AddrLocation::*;

    let mut output = Vec::with_capacity(blocks.len());

    for block in blocks {
        let (proc_block, external_labels) = block.into_proc_block();
        let block_name = &proc_block.block.name;
        let mut unresolved = UnresolvedBlockLabels::new(block_name);

        println!("First pass on external labels for {}", &block_name);
        for (addr, mut label) in external_labels {
            match memory_map.get_addr_location(addr, block_name) {
                NotFound => unresolved.not_found.get_or_insert_with(Vec::new).push({
                    label.set_not_found();
                    label
                }),
                Multiple(hits) => unresolved.multiple.get_or_insert_with(Vec::new).push({
                    label.set_unresolved(hits);
                    label
                }),
                Single(block) => {
                    // check if label already exists before inserting...?
                    if let Some(ovl_labels) = label_set.overlays.get_mut(&block) {
                        println!(
                            "{:4}Found single overlay from '{}' into '{}': {:x?}",
                            "", &block_name, &block, &label
                        );
                        if !ovl_labels.contains_key(&addr) {
                            label.set_overlay(&block);
                            ovl_labels.insert(addr, label);
                            println!("{:4}Label not found; inserted!", "");
                        }
                    } else {
                        // must be a label from a global symbol
                        println!(
                            "{:4}Found global label from '{}' into '{}': {:x?}",
                            "", &block_name, &block, &label
                        );
                        if label_set.globals.contains_key(&addr) {
                            label.set_global();
                            label_set.globals.insert(addr, label);
                            println!("{:4}Global label not found; inserted!", "");
                        }
                    }
                }
            }
        }
        output.push((proc_block, unresolved));
    }

    output
}

/// Hold any `Label`s that couldn't be found or resolved into a single overlay.
/// The label originates from `block`
#[derive(Debug)]
struct UnresolvedBlockLabels<'c> {
    block: &'c BlockName,
    multiple: Option<Vec<Label>>,
    not_found: Option<Vec<Label>>,
}

impl<'c> UnresolvedBlockLabels<'c> {
    fn new(block: &'c BlockName) -> Self {
        Self {
            block,
            multiple: None,
            not_found: None,
        }
    }

    fn resolve_multi_labels(&mut self, label_set: &mut LabelSet) {
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
        let fold_new_multilabels =
            |mut acc: Vec<Label>, (mut label, new_found): (Label, Vec<BlockName>)| {
                println!(
                    "{:4}Found label {:08x} <{:?}> in {:x?}",
                    "", label.addr, label.kind, &new_found
                );
                println!("{:8}Used to be in {:x?}", "", &label.location);

                // Set Label.location here ?
                match new_found.len() {
                    // `label` was not in any other blocks, so can't reduce possibilities
                    // The label already is tied to the `Vec` of possible blocks, so
                    // just put the label back into the unresolved pile
                    0 => {
                        acc.push(label);
                    }
                    // `label` is already present in exactly one other block; nothing to do
                    1 => (),
                    // A matching `Label` was found in >1 other blocks. Reduce the possibilites
                    // for this label
                    _ => {
                        label.set_multiple(new_found);
                        acc.push(label);
                    }
                }

                acc
            };

        if let Some(multiple) = self.multiple.take() {
            let max = multiple.len();

            println!("Resolving multi-block labels from {}", self.block);
            let fitlered_mutliple = multiple
                .into_iter()
                .map(find_label_already_in_blocks)
                .fold(Vec::with_capacity(max), fold_new_multilabels);

            self.multiple.replace(fitlered_mutliple);
        }
    }

    fn into_components(self) -> (Option<Vec<Label>>, Option<Vec<Label>>) {
        (self.multiple, self.not_found)
    }
}

fn combine_internal_labels<'c>(
    label_set: &mut LabelSet,
    blocks: Vec<LabeledBlock<'c>>,
) -> Vec<ExternLabeledBlock<'c>> {
    let fold_into_externblock =
        |mut acc: Vec<ExternLabeledBlock<'c>>,
         (extrn_block, internal_labels): (ExternLabeledBlock<'c>, HashMap<u32, Label>)| {
            let block_name = &extrn_block.block.name;

            // All internal `Label`s have their block name set; this only
            // needs to be changed for the global labels:
            //  to `global` from the specific global code block name
            if let Some(ovl_labels) = label_set.overlays.get_mut(block_name) {
                ovl_labels.extend(internal_labels);
            } else {
                let corrected_iter = internal_labels.into_iter().map(|(addr, mut label)| {
                    label.set_global();

                    (addr, label)
                });

                label_set.globals.extend(corrected_iter);
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

pub struct LabeledBlock<'c> {
    pub instructions: Vec<Instruction>,
    pub block: &'c CodeBlock,
    pub internal_labels: HashMap<u32, Label>,
    pub external_labels: HashMap<u32, Label>,
}

impl<'c> LabeledBlock<'c> {
    fn into_extern_labeled(self) -> (ExternLabeledBlock<'c>, HashMap<u32, Label>) {
        let Self {
            instructions,
            block,
            internal_labels,
            external_labels,
        } = self;
        (
            ExternLabeledBlock {
                instructions,
                block,
                external_labels,
            },
            internal_labels,
        )
    }
}

struct ExternLabeledBlock<'c> {
    instructions: Vec<Instruction>,
    block: &'c CodeBlock,
    external_labels: HashMap<u32, Label>,
}

impl<'c> ExternLabeledBlock<'c> {
    fn into_proc_block(self) -> (ProcessedBlock<'c>, HashMap<u32, Label>) {
        let Self {
            instructions,
            block,
            external_labels,
        } = self;
        (
            ProcessedBlock {
                instructions,
                block,
            },
            external_labels,
        )
    }
}

struct ProcessedBlock<'c> {
    instructions: Vec<Instruction>,
    block: &'c CodeBlock,
}
