mod instruction;
pub mod memmap;
mod mipsvals;
mod pass1;

use crate::config::RawLabel;
use err_derive::Error;
use memmap::BlockName;
use std::collections::{HashMap, HashSet};

pub use pass1::pass1;

#[derive(Debug, Eq, PartialEq)]
pub enum LabelKind {
    // branch target, typically
    Local,
    // subroutine start, typically
    Routine,
    Data,
    // named label from input config file
    Named(String),
}

#[derive(Debug)]
enum LabelLoc {
    // Initial state of a label
    Unspecified,
    // label is in a global memory location (always loaded and singularly mapped to an address)
    Global,
    // label is in one overlayed memory location (not always loaded)
    Overlayed(BlockName),
    // label matches locations of found labels in mutliple overlays
    Multiple(Vec<BlockName>),
    // label's location is within the memory region that could map to multiple overlays
    UnresolvedMultiple(Vec<BlockName>),
    // label doesn't map into any known memory region. Could be
    NotFound,
}

impl From<Option<&BlockName>> for LabelLoc {
    fn from(block: Option<&BlockName>) -> Self {
        block
            .map(|name| LabelLoc::Overlayed(name.clone()))
            .unwrap_or(LabelLoc::Unspecified)
    }
}

#[derive(Debug)]
pub struct Label {
    addr: u32,
    kind: LabelKind,
    location: LabelLoc,
}

impl Label {
    pub fn set_overlay(&mut self, ovl: &BlockName) {
        self.location = LabelLoc::Overlayed(ovl.clone());
    }

    pub fn set_global(&mut self) {
        self.location = LabelLoc::Global;
    }

    pub fn set_not_found(&mut self) {
        self.location = LabelLoc::NotFound;
    }

    pub fn set_unresolved(&mut self, blocks: Vec<BlockName>) {
        self.location = LabelLoc::UnresolvedMultiple(blocks);
    }

    pub fn set_multiple(&mut self, blocks: Vec<BlockName>) {
        self.location = LabelLoc::Multiple(blocks);
    }

    pub fn get_possible_blocks(&self) -> Option<&[BlockName]> {
        match &self.location {
            LabelLoc::Multiple(blocks) => Some(&blocks),
            LabelLoc::UnresolvedMultiple(blocks) => Some(&blocks),
            _ => None,
        }
    }

    pub fn local(addr: u32, ovl: Option<&BlockName>) -> Self {
        Self {
            addr,
            kind: LabelKind::Local,
            location: ovl.into(),
        }
    }

    pub fn routine(addr: u32, ovl: Option<&BlockName>) -> Self {
        Self {
            addr,
            kind: LabelKind::Routine,
            location: ovl.into(),
        }
    }

    pub fn data(addr: u32, ovl: Option<&BlockName>) -> Self {
        Self {
            addr,
            kind: LabelKind::Data,
            location: ovl.into(),
        }
    }
}

impl From<RawLabel> for Label {
    fn from(r: RawLabel) -> Self {
        use LabelLoc::{Overlayed, Unspecified};

        let (addr, symbol, location) = match r {
            RawLabel::Global(a, s) => (a, s, Unspecified),
            RawLabel::Overlayed(a, s, o) => (a, s, Overlayed(o.into())),
        };
        let kind = LabelKind::Named(symbol);

        Self {
            addr,
            kind,
            location,
        }
    }
}

#[derive(Debug)]
pub struct LabelSet {
    // map from vaddr to label
    globals: HashMap<u32, Label>,
    // for easy search later...?
    // base_ovl: HashMap<String, HashMap<u32, Label>>,
    // Map<Overlay Name => Map<Vaddr => Label>>
    overlays: HashMap<BlockName, HashMap<u32, Label>>,
}

impl LabelSet {
    pub fn from_config(raw: Vec<RawLabel>, ovls: &HashSet<BlockName>) -> Result<Self, LabelSetErr> {
        let ovl_count = ovls.len();
        // Create maps for global symbols (addr => label)
        // and for overlay specific symbols (overlay => addr => label)
        let mut globals = HashMap::new();
        let mut overlays = ovls
            .iter()
            .fold(HashMap::with_capacity(ovl_count), |mut map, ovl| {
                map.insert(ovl.clone(), HashMap::new());
                map
            });

        for raw_label in raw {
            match raw_label {
                RawLabel::Global(..) => {
                    let label = Label::from(raw_label);
                    globals.insert(label.addr, label);
                }
                RawLabel::Overlayed(addr, ref symbol, ref ovl) => {
                    let ovl_labels = overlays.get_mut(ovl.as_str()).ok_or_else(|| {
                        LabelSetErr::UnknownOverlay(addr, symbol.clone(), ovl.clone())
                    })?;
                    let label = Label::from(raw_label);
                    ovl_labels.insert(label.addr, label);
                }
            };
        }

        Ok(Self { globals, overlays })
    }
}

#[derive(Debug, Error)]
pub enum LabelSetErr {
    #[error(
        display = r#"Overlay "{}" not listed in config overlays, but it was listed as the overlay for label "{}" ({:#08x})"#,
        _2,
        _1,
        _0
    )]
    UnknownOverlay(u32, String, String),
}
