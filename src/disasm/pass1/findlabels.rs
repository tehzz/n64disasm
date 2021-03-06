use crate::disasm::labels::{Label, LabelKind, LabelSet};
use crate::disasm::memmap::{BlockName, BlockRange, Section};
use crate::disasm::pass1::{
    linkinsn::{Link, LinkedVal},
    parsedata::{FindDataIter, ParsedData},
    BlockLoadedSections, DataEntry, Instruction, JumpKind,
};
use log::debug;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;

/// A collection of addresses and labels generated from parsing instructions.
/// The labels in `internals` and `externals` are all not named, and will have
/// auto-generated name. Named labels will come from the config, and are located
/// in the `existing_labels` map
#[derive(Debug)]
pub struct LabelState<'a, 'rom> {
    name: &'a BlockName,
    range: &'a BlockRange,
    /// slice of rom data that maps to the loaded code/data of `range`
    rom: &'rom [u8],
    /// global scope labels in the config
    config_global: &'a HashMap<u32, Label>,
    /// labels in the config for this overlay (if applicable)
    config_ovl: Option<&'a HashMap<u32, Label>>,
    /// subroutines or data that are located in the current block
    pub internals: HashMap<u32, Label>,
    /// subroutines or data that are not in the current block
    pub externals: HashMap<u32, Label>,
    /// interperted data from the `rom` slice
    pub data: BTreeMap<u32, DataEntry<'rom>>,
    /// Addresses that have labels in the existing maps, typically from the config.
    /// These labels will be either global or internal
    pub existing_labels: HashMap<u32, ConfigLabelLoc>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConfigLabelLoc {
    Internal,
    Global,
}

impl<'a, 'rom> LabelState<'a, 'rom> {
    /// Set up a new labeling state based on a block's memory range and known labels
    /// passed in the from the configuration yaml file.
    pub fn from_config(
        range: &'a BlockRange,
        rom: &'rom [u8],
        set: &'a LabelSet,
        name: &'a BlockName,
    ) -> Self {
        Self {
            name,
            range,
            rom,
            config_global: &set.globals,
            config_ovl: set.overlays.get(name),
            internals: HashMap::new(),
            externals: HashMap::new(),
            data: BTreeMap::new(),
            existing_labels: HashMap::new(),
        }
    }

    /// extract a (possible) label from an instruction. This doesn't deal with
    /// assigning an overlay to a label
    /// Branch => local label
    /// J => internal or external subroutine
    /// Linked (Not float or immediate) => data label
    pub fn check_instruction(&mut self, insn: &Instruction) {
        use JumpKind::*;
        use LinkedVal::*;

        match insn.jump {
            Branch(addr) | BAL(addr) | BranchCmp(addr) => self.insert_local(addr),
            Jump(addr) | JAL(addr) => self.insert_subroutine(addr),
            JumpRegister(..) | NoJump => (),
        };
        //TODO: early return?
        match insn.linked {
            Pointer(Link { value, .. })
            | PtrOff(Link { value, .. }, ..)
            | PtrEmbed(Link { value, .. }) => self.insert_data(value),
            FloatPtr(Link { value, .. }) => self.insert_float(value),
            DoublePtr(Link { value, .. }) => self.insert_double(value),
            Empty | PtrLui(..) | Immediate(..) | ImmLui(..) | Float(..) | FloatLoad(..) => (),
        }
    }

    /// Check that all of the internal labels are in the proper loaded (.text or .data)
    /// sections. There can be mismatches due to things like used function pointers
    /// before reaching a routine
    pub fn ensure_internal_label_section(&mut self, sections: &BlockLoadedSections) {
        self.internals
            .iter_mut()
            .filter_map(|(&addr, label)| {
                sections
                    .find_address(addr)
                    .map(|section| (label, section.kind))
            })
            .for_each(|(label, section)| label.update_kind(section));
    }

    /// Check through the found .data sections to see if there are any string, pointers,
    /// or jump tables. If so, parse that data and add labels to that data (if needed)
    pub fn find_and_add_data(&mut self, sections: &BlockLoadedSections, expak: bool) {
        let block_vram_start = self.range.get_ram_start() as u32;
        for sec in sections.iter_data() {
            let start_vram = sec.range.start;
            let start_idx = (start_vram - block_vram_start) as usize;
            let end_idx = (sec.range.end - block_vram_start) as usize;
            let data_buf = &self.rom[start_idx..end_idx];
            let known = Some(&self.data);

            let parsed_iter = FindDataIter::new(data_buf, start_vram, sections, expak, known)
                .expect("valid data section");

            parsed_iter.for_each(|res| {
                let entry = res.unwrap();
                insert_parsed_data_entry(self, entry, sections);
            });
        }
    }

    /// check if a given addr is a known label from the config file,
    /// either in the global label map, or in this overlay's map (if applicable)
    #[allow(clippy::map_entry)]
    fn addr_in_config(&mut self, addr: u32) -> bool {
        if self.existing_labels.contains_key(&addr) {
            true
        } else if self.config_global.contains_key(&addr) {
            self.existing_labels.insert(addr, ConfigLabelLoc::Global);
            true
        } else if self
            .config_ovl
            .map(|s| s.contains_key(&addr))
            .unwrap_or(false)
        {
            self.existing_labels.insert(addr, ConfigLabelLoc::Internal);
            true
        } else {
            false
        }
    }

    /// check if a given addr is contained within this state's memory range
    fn is_internal(&self, addr: u32) -> bool {
        self.range.contains(addr)
    }
    /// check if a given addr is contained within this state's .text/.data sections
    fn is_internal_loaded(&self, addr: u32) -> bool {
        self.range.load_contains(addr)
    }

    fn insert_local(&mut self, addr: u32) {
        self.insert_local_address(addr, Label::local, |ls, addr| {
            !ls.internals.contains_key(&addr)
        });
    }
    fn insert_subroutine(&mut self, addr: u32) {
        self.insert_address(addr, Label::routine);
    }
    fn insert_data(&mut self, addr: u32) {
        self.insert_address(addr, Label::data);
    }
    fn insert_jmptbl(&mut self, addr: u32) {
        // replace any existing labels with a jumptable label
        self.insert_local_address(addr, Label::jmp_tbl, |_, _| true);
    }
    fn insert_float(&mut self, addr: u32) {
        self.insert_address(addr, Label::data);

        if self.is_internal_loaded(addr) {
            let idx = self.address_to_offset(addr);
            let bytes: [u8; 4] = self.rom[idx..idx + 4].try_into().unwrap();
            let hex = u32::from_be_bytes(bytes);

            self.data.insert(addr, DataEntry::float(addr, hex));
        }
    }

    fn insert_double(&mut self, addr: u32) {
        self.insert_address(addr, Label::data);

        if self.is_internal_loaded(addr) {
            let idx = self.address_to_offset(addr);
            let bytes: [u8; 8] = self.rom[idx..idx + 8].try_into().unwrap();
            let hex = u64::from_be_bytes(bytes);

            self.data.insert(addr, DataEntry::double(addr, hex));
        }
    }

    fn insert_address(&mut self, addr: u32, label_fn: LabelMaker) {
        if self.addr_in_config(addr) {
            return;
        }

        if self.is_internal(addr) {
            let name = &self.name;
            self.internals
                .entry(addr)
                .or_insert_with(|| label_fn(addr, Some(name)));
        } else {
            self.externals
                .entry(addr)
                .or_insert_with(|| label_fn(addr, None));
        }
    }

    fn insert_local_address(&mut self, addr: u32, label_fn: LabelMaker, check: LabelChecker) {
        if !self.is_internal(addr) {
            // Probably capstone disassembling data as instructions
            debug!(
                "Addr {:x?} not in memory for {} [{:x?}]",
                addr, self.name, self.range
            );
            return;
        }

        if self.addr_in_config(addr) {
            return;
        }

        if check(&self, addr) {
            self.internals.insert(addr, label_fn(addr, Some(self.name)));
        }
    }

    fn address_to_offset(&self, addr: u32) -> usize {
        (addr - self.range.get_ram_start()) as usize
    }
}

type LabelMaker = fn(u32, Option<&BlockName>) -> Label;
type LabelChecker = fn(&LabelState, u32) -> bool;

fn insert_parsed_data_entry<'rom>(
    ls: &mut LabelState<'_, 'rom>,
    entry: DataEntry<'rom>,
    secs: &BlockLoadedSections,
) {
    use ParsedData::*;
    // dont' use this entry if there's an issue
    if exclude_entry(&entry, secs) {
        return;
    }

    // add any labels to found data, if necessary
    match &entry.data {
        Float(..) => return ls.insert_float(entry.addr),
        Double(..) => return ls.insert_double(entry.addr),
        JmpTbl(..) => ls.insert_jmptbl(entry.addr),
        Asciz(..) | Ptr(..) => (),
    };
    // add any "sub-labels" passed on parsed data
    match &entry.data {
        Ptr(ptr) => insert_unk_ptr(ls, *ptr, secs),
        JmpTbl(ts) => insert_jmptbl_targets(ls, ts),
        Asciz(..) => (),
        Float(..) | Double(..) => unreachable!(),
    }
    // store parsed data, if not already there due to parsing the instructions
    if let Some(old) = ls.data.get(&entry.addr) {
        let replace = match (&old.data, &entry.data) {
            (Float(..), _) => false,
            (Double(..), _) => false,
            _ => true,
            // local branch to data?
        };
        if replace {
            ls.data.insert(entry.addr, entry);
        }
    } else {
        match &entry.data {
            Ptr(..) | Asciz(..) => {
                ls.data.insert(entry.addr, entry);
            }
            JmpTbl(ts) => store_jmbtbl_as_ptrs(ls, ts, entry.addr),
            Float(..) | Double(..) => unreachable!(),
        };
    }
}

fn exclude_entry(entry: &DataEntry<'_>, sections: &BlockLoadedSections) -> bool {
    use ParsedData::*;

    match entry.data {
        Ptr(p) => {
            let sec = sections.find_address(p).map(|s| s.kind);
            match sec {
                // exclude any pointers to .text that are not 4 byte aligned
                Some(Section::Text) => p % 4 != 0,
                _ => false,
            }
        }
        _ => false,
    }
}

fn insert_unk_ptr(ls: &mut LabelState, ptr: u32, sections: &BlockLoadedSections) {
    let section = sections.find_address(ptr).map(|s| s.kind);

    // TODO: local branch to subroutine if found stored? (cf .4byte .L)
    match section {
        Some(Section::Text) => ls.insert_subroutine(ptr),
        // Either Section::Data, bss, or external
        _ => ls.insert_data(ptr),
    }
}

fn insert_jmptbl_targets(ls: &mut LabelState, targets: &[u32]) {
    for &target in targets {
        ls.insert_local_address(target, Label::jmp_target, |ls, addr| {
            ls.internals
                .get(&addr)
                .map_or(true, |l| l.kind == LabelKind::Local)
        })
    }
}

/// Store the actual found pointers of a jump table as individual parsed pointers.
/// so that labels/pointers to the jump table entries can be easily printed
fn store_jmbtbl_as_ptrs(ls: &mut LabelState, targets: &[u32], start: u32) {
    targets
        .iter()
        .copied()
        .enumerate()
        .map(|(i, t)| DataEntry::ptr(start + i as u32 * 4, t))
        .for_each(|entry| {
            ls.data.insert(entry.addr, entry);
        })
}
