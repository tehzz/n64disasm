use crate::disasm::labels::{Label, LabelSet};
use crate::disasm::memmap::{BlockName, BlockRange};
use crate::disasm::pass1::{
    linkinsn::{Link, LinkedVal},
    Instruction, JumpKind,
};
use std::collections::HashMap;

/// The structure that collects addresses for labels as parsed instructions
/// from capstone are folded at the end of pass1
#[derive(Debug)]
pub struct LabelState<'c> {
    name: &'c BlockName,
    range: &'c BlockRange,
    config_global: &'c HashMap<u32, Label>,
    config_ovl: Option<&'c HashMap<u32, Label>>,
    pub internals: HashMap<u32, Label>,
    pub externals: HashMap<u32, Label>, // subroutines or data that are not in the current block
}

impl<'c> LabelState<'c> {
    /// Set up a new labeling state based on a block's memory range and known labels
    /// passed in the from the configuration yaml file.
    pub fn from_config(range: &'c BlockRange, set: &'c LabelSet, name: &'c BlockName) -> Self {
        Self {
            name,
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
    /// Linked (Not float or immediate) => data label
    pub fn check_instruction(&mut self, insn: &Instruction) {
        use JumpKind::*;
        use LinkedVal::*;

        match insn.jump {
            Branch(addr) | BAL(addr) => self.insert_local(addr),
            Jump(addr) | JAL(addr) => self.insert_subroutine(addr),
            _ => (),
        };
        //TODO: early return?
        match insn.linked {
            Pointer(Link { value, .. }) | PtrOff(Link { value, .. }, ..) => self.insert_data(value),
            _ => (),
        }
    }

    /// check if a given addr is a known label from the config file,
    /// either in the global label map, or in this overlay's map (if applicable)
    fn is_in_config_labels(&self, addr: u32) -> bool {
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
        if self.is_in_config_labels(addr) {
            return;
        }

        if !self.internals.contains_key(&addr) {
            self.internals
                .insert(addr, Label::local(addr, Some(self.name)));
        }
    }
    fn insert_subroutine(&mut self, addr: u32) {
        if self.is_in_config_labels(addr) {
            return;
        }

        if self.is_internal(addr) {
            if !self.internals.contains_key(&addr) {
                self.internals
                    .insert(addr, Label::routine(addr, Some(self.name)));
            }
        } else if !self.externals.contains_key(&addr) {
            self.externals.insert(addr, Label::routine(addr, None));
        }
    }
    fn insert_data(&mut self, addr: u32) {
        if self.is_in_config_labels(addr) {
            return;
        }

        if self.is_internal(addr) {
            if !self.internals.contains_key(&addr) {
                self.internals
                    .insert(addr, Label::data(addr, Some(self.name)));
            }
        } else if !self.externals.contains_key(&addr) {
            self.externals.insert(addr, Label::data(addr, None));
        }
    }
}
