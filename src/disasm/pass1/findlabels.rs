use crate::disasm::labels::{Label, LabelSet};
use crate::disasm::memmap::{BlockName, BlockRange};
use crate::disasm::pass1::{
    linkinsn::{Link, LinkedVal},
    BlockLoadedSections, DataEntry, Instruction, JumpKind,
};
use std::collections::HashMap;
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
    pub data: HashMap<u32, DataEntry<'rom>>,
    /// Addresses that have labels in the existing maps, typicall from the config.
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
            data: HashMap::new(),
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

    /// check if a given addr is a known label from the config file,
    /// either in the global label map, or in this overlay's map (if applicable)
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
    fn is_interal_loaded(&self, addr: u32) -> bool {
        self.range.load_contains(addr)
    }

    fn insert_local(&mut self, addr: u32) {
        if self.addr_in_config(addr) {
            return;
        }

        if !self.internals.contains_key(&addr) {
            self.internals
                .insert(addr, Label::local(addr, Some(self.name)));
        }
    }
    fn insert_subroutine(&mut self, addr: u32) {
        self.insert_address(addr, Label::routine);
    }
    fn insert_data(&mut self, addr: u32) {
        self.insert_address(addr, Label::data);
    }
    fn insert_float(&mut self, addr: u32) {
        self.insert_address(addr, Label::data);

        if self.is_interal_loaded(addr) {
            let idx = self.address_to_offset(addr);
            let bytes: [u8; 4] = self.rom[idx..idx + 4].try_into().unwrap();
            let hex = u32::from_be_bytes(bytes);

            self.data.insert(addr, DataEntry::float(addr, hex));
        }
    }

    fn insert_double(&mut self, addr: u32) {
        self.insert_address(addr, Label::data);

        if self.is_interal_loaded(addr) {
            let idx = self.address_to_offset(addr);
            let bytes: [u8; 8] = self.rom[idx..idx + 8].try_into().unwrap();
            let hex = u64::from_be_bytes(bytes);

            self.data.insert(addr, DataEntry::double(addr, hex));
        }
    }

    fn insert_address(&mut self, addr: u32, label_fn: LabelInsert) {
        if self.addr_in_config(addr) {
            return;
        }

        if self.is_internal(addr) {
            if !self.internals.contains_key(&addr) {
                self.internals.insert(addr, label_fn(addr, Some(self.name)));
            }
        } else if !self.externals.contains_key(&addr) {
            self.externals.insert(addr, label_fn(addr, None));
        }
    }

    fn address_to_offset(&self, addr: u32) -> usize {
        (addr - self.range.get_ram_start()) as usize
    }
}

type LabelInsert = fn(u32, Option<&BlockName>) -> Label;
