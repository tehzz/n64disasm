mod pass1;

use crate::config::{RawCodeBlock, RawLabel};
use err_derive::Error;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

pub use pass1::pass1;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Overlay(Rc<str>);

impl From<String> for Overlay {
    fn from(s: String) -> Self {
        Self(Rc::from(s))
    }
}

impl From<Rc<str>> for Overlay {
    fn from(r: Rc<str>) -> Self {
        Self(r)
    }
}

impl Borrow<str> for Overlay {
    fn borrow(&self) -> &str {
        Borrow::borrow(&self.0)
    }
}

pub type OverlaySet = HashMap<Overlay, HashSet<Overlay>>;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockKind {
    Global,
    BaseOverlay,
    Overlay,
}

#[derive(Debug)]
pub struct CodeBlock {
    pub rom_start: u32,
    pub rom_end: u32,
    pub name: Rc<str>,
    pub vaddr: u32,
    pub kind: BlockKind,
}

impl CodeBlock {
    pub fn from_raw(raw: RawCodeBlock, kind: BlockKind) -> Self {
        Self {
            rom_start: raw.0,
            rom_end: raw.1,
            name: Rc::from(raw.2),
            vaddr: raw.3,
            kind,
        }
    }
}

#[derive(Debug)]
pub struct Label {
    addr: u32,
    symbol: String,
    /// None is a global symbol
    overlay: Option<Overlay>,
}

impl From<RawLabel> for Label {
    fn from(r: RawLabel) -> Self {
        let (addr, symbol, overlay) = match r {
            RawLabel::Global(a, s) => (a, s, None),
            RawLabel::Overlayed(a, s, o) => (a, s, Some(o.into())),
        };

        Self {
            addr,
            symbol,
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
    overlays: HashMap<Overlay, HashMap<u32, Label>>,
}

impl LabelSet {
    pub fn from_raw_labels(
        raw: Vec<RawLabel>,
        ovls: &HashSet<Overlay>,
    ) -> Result<Self, LabelSetError> {
        let mut globals = HashMap::new();
        let mut overlays = HashMap::new();

        for raw_label in raw {
            match raw_label {
                RawLabel::Global(..) => {
                    let label = Label::from(raw_label);
                    globals.insert(label.addr, label);
                }
                RawLabel::Overlayed(addr, symbol, ovl) => {
                    if !ovls.contains(ovl.as_str()) {
                        return Err(LabelSetError::UnknownOverlay(addr, symbol, ovl));
                    }
                    let overlay = Overlay::from(ovl);
                    let label = Label {
                        addr,
                        symbol,
                        overlay: Some(overlay.clone()),
                    };
                    overlays
                        .entry(overlay)
                        .or_insert_with(HashMap::new)
                        .insert(label.addr, label);
                }
            };
        }

        Ok(Self { globals, overlays })
    }
}

#[derive(Debug, Error)]
pub enum LabelSetError {
    #[error(
        display = r#"Overlay "{}" not listed in config overlays, but it was listed as the overlay for label "{}" ({:#08x})"#,
        _2,
        _1,
        _0
    )]
    UnknownOverlay(u32, String, String),
}
