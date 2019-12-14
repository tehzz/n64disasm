mod jumps;
mod labeling;
mod linkinsn;

use crate::config::Config;
use crate::disasm::{
    instruction::{InsnParseErr, Instruction},
    memmap::{AddrLocation, BlockName, CodeBlock, MemoryMap},
    mipsvals::*,
    Label, LabelSet,
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

type P1Result<T> = Result<T, Pass1Error>;

fn get_cs_instance() -> Result<Capstone, capstone::Error> {
    Capstone::new()
        .mips()
        .detail(true)
        .mode(arch::mips::ArchMode::Mips64)
        .endian(capstone::Endian::Big)
        .build()
}

pub fn pass1(config: Config, rom: &Path) -> P1Result<()> {
    let Config {
        memory: memory_map,
        labels: mut config_labels,
    } = config;
    let cs = get_cs_instance()?;

    let mut rom = File::open(rom)?;
    let read_rom = |block| read_codeblock(block, &mut rom);
    let proc_insns = |res| process_block(res, &config_labels, &cs);

    let labeled_blocks = memory_map
        .blocks
        .iter()
        .map(read_rom)
        .map(proc_insns)
        .collect::<P1Result<Vec<_>>>()?;

    combine_labels(&mut config_labels, &memory_map, labeled_blocks);

    Ok(())
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

    println!("Found {} instructions in block '{}'", num_insn, &block.name);

    let label_state = LabelState::from_config(&block.range, &labels, &block.name);

    let FoldInsnState {
        instructions,
        label_state,
        ..
    } = cs_instructions
        .iter()
        //.take(5000)
        //.inspect(|i| println!("{}", i))
        .map(|i| {
            let detail = cs.insn_detail(&i)?;
            Instruction::from_components(&i, &detail)
        })
        .scan(NLState::Clear, |s, res| {
            Some(res.map(|i| indicate_newlines(s, i)))
        })
        .enumerate()
        .try_fold(FoldInsnState::new(num_insn, label_state), fold_instructions)?;

    let LabelState {
        internals: internal_labels,
        externals: external_labels,
        ..
    } = label_state;

    Ok(LabeledBlock {
        instructions,
        block,
        internal_labels,
        external_labels,
    })
}

/* Symbol Name Resolution Ideas
  1) Collect internal symbols from all blocks into two hashmaps:
        Global: addr => Label
        Overlays: Overlay => Map { addr => Label }
     Do this by combining the config label lists with found symbols
     Also, add the overlay name to any found symbols
  2) Collect external symbols into a similar setup
  3) Go through external symbols to try to resolve. Do this by making a
     "memory map" struct that can take an address and output N (1+) number of
     blocks that the address is in
        a) For externals from global blocks, they could go anywhere, so have to check full map
        b) For externals from overlayed blocks, they could be in the static sections or
           in the set of loaded overlays; thus, need a limited "submap"
  4) If a symbol can only be in one block, resolve that symbol.
     Collect symbols that could be in more than one block.
  5) Try to resolve symbols in more than one block
        a) see if the symbol is now in one of those blocks (it was resolved somewhere else)
        b) if not..?
*/

fn combine_labels(label_set: &mut LabelSet, memory_map: &MemoryMap, blocks: Vec<LabeledBlock>) {
    let external_labeled_blocks = combine_internal_labels(label_set, blocks);
    let (final_blocks, unresolved_labels) =
        combine_unique_external_labels(label_set, memory_map, external_labeled_blocks);

    println!("\nUnresolved Labels:");
    let mut total = 0;
    for mut unresolved_labels in unresolved_labels {
        let new_unres = unresolved_labels
            .multiple
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0);
        total += new_unres;

        println!(
            "Found {:?} unresolved multi-block lables in {}",
            new_unres, unresolved_labels.block
        );
        unresolved_labels.resolve_multi_labels(label_set);
    }
    println!("Total unresolved multi-block: {}", total);
}

fn combine_unique_external_labels<'c>(
    label_set: &mut LabelSet,
    memory_map: &MemoryMap,
    blocks: Vec<ExternLabeledBlock<'c>>,
) -> (Vec<ProcessedBlock<'c>>, Vec<UnresolvedBlockLabels<'c>>) {
    use AddrLocation::*;

    let mut output_blocks = Vec::with_capacity(blocks.len());
    let mut unresolved_blocks = Vec::with_capacity(blocks.len());

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
                Single(ovl) => {
                    // check if label already exists before inserting...?
                    if let Some(ovl_labels) = label_set.overlays.get_mut(&ovl) {
                        label.set_overlay(&ovl);
                        println!(
                            "{:4}Found single overlay from '{}' into '{}': {:?}",
                            "", &block_name, &ovl, &label
                        );
                        ovl_labels.insert(addr, label);
                    } else {
                        // must be a label from a global symbol
                        label.set_global();
                        println!(
                            "{:4}Found global label from '{}' into '{}': {:x?}",
                            "", &block_name, &ovl, &label
                        );
                        label_set.globals.insert(addr, label);
                    }
                }
            }
        }
        output_blocks.push(proc_block);
        unresolved_blocks.push(unresolved);
    }

    (output_blocks, unresolved_blocks)
}

/// Hold any `Label`s that couldn't be found or resolved into a single overlay.
/// The label originates from `block`
#[derive(Debug)]
struct UnresolvedBlockLabels<'c> {
    block: &'c BlockName,
    not_found: Option<Vec<Label>>,
    multiple: Option<Vec<Label>>,
}

impl<'c> UnresolvedBlockLabels<'c> {
    fn new(block: &'c BlockName) -> Self {
        Self {
            block,
            not_found: None,
            multiple: None,
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
                        .map(|found_label| label.kind == found_label.kind)
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
                    "{:4}Found label {:08x} in {:x?}",
                    "", label.addr, &new_found
                );
                println!("{:8}Used to be in {:x?}", "", &label.location);

                // Set Label.location here ?
                match new_found.len() {
                    // `label` was not in any other blocks, so can't reduce possibilities
                    // The label already is tied to the `Vec` of possible blocks; nothing to do
                    0 => (),
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
}

fn combine_internal_labels<'c>(
    label_set: &mut LabelSet,
    blocks: Vec<LabeledBlock<'c>>,
) -> Vec<ExternLabeledBlock<'c>> {
    let output = Vec::with_capacity(blocks.len());

    blocks
        .into_iter()
        .map(LabeledBlock::into_extern_labeled)
        .fold(output, |mut acc, (extrn_block, internal_labels)| {
            let block_name = &extrn_block.block.name;

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
        })
}

struct LabeledBlock<'c> {
    instructions: Vec<Instruction>,
    block: &'c CodeBlock,
    internal_labels: HashMap<u32, Label>,
    external_labels: HashMap<u32, Label>,
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

    // store any labels that were generated by this newly inserted instruction
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
