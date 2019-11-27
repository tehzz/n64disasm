mod instruction;
pub mod memmap;
mod mipsvals;
mod pass1;

use crate::config::RawLabel;
use err_derive::Error;
use memmap::BlockName;
use std::collections::{HashMap, HashSet};

pub use pass1::pass1;

#[derive(Debug)]
pub enum LabelKind {
    Local,
    GlobalRoutine,
    Data,
    Named(String),
}

#[derive(Debug)]
pub struct Label {
    addr: u32,
    kind: LabelKind,
    /// None is a global symbol
    overlay: Option<BlockName>,
}

impl Label {
    pub fn add_overlay(&mut self, ovl: &BlockName) {
        self.overlay = Some(ovl.clone());
    }

    pub fn local(addr: u32) -> Self {
        Self {
            addr,
            kind: LabelKind::Local,
            overlay: None,
        }
    }

    pub fn global(addr: u32) -> Self {
        Self {
            addr,
            kind: LabelKind::GlobalRoutine,
            overlay: None,
        }
    }

    pub fn data(addr: u32) -> Self {
        Self {
            addr,
            kind: LabelKind::Data,
            overlay: None,
        }
    }
}

impl From<RawLabel> for Label {
    fn from(r: RawLabel) -> Self {
        let (addr, symbol, overlay) = match r {
            RawLabel::Global(a, s) => (a, s, None),
            RawLabel::Overlayed(a, s, o) => (a, s, Some(o.into())),
        };
        let kind = LabelKind::Named(symbol);

        Self {
            addr,
            kind,
            overlay,
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
