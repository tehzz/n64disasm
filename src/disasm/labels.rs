use crate::config::RawLabel;
use crate::disasm::memmap::{BlockName, Section};
use err_derive::Error;
use log::trace;
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum LabelKind {
    // branch target, typically
    Local,
    // subroutine start, typically
    Routine,
    // start of a jump table
    JmpTbl,
    // pointer to instructions in a jump table
    JmpTarget,
    // a pointer to some sort of data (.data, .rodata, .bss)
    Data,
    // named label from input config file
    Named(String),
}

#[derive(Debug, Clone)]
pub enum LabelLoc {
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
    // label doesn't map into any known memory region. Could be MMIO, or an issue with label parsing
    NotFound,
}

impl From<Option<&BlockName>> for LabelLoc {
    fn from(block: Option<&BlockName>) -> Self {
        block
            .map(|name| LabelLoc::Overlayed(name.clone()))
            .unwrap_or(LabelLoc::Unspecified)
    }
}

#[derive(Debug, Clone)]
pub struct Label {
    pub addr: u32,
    pub kind: LabelKind,
    pub location: LabelLoc,
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

    pub fn is_named(&self) -> bool {
        match self.kind {
            LabelKind::Named(_) => true,
            _ => false,
        }
    }

    // constructors
    pub fn local(addr: u32, ovl: Option<&BlockName>) -> Self {
        Label::from_kind(addr, ovl, LabelKind::Local)
    }
    pub fn routine(addr: u32, ovl: Option<&BlockName>) -> Self {
        Label::from_kind(addr, ovl, LabelKind::Routine)
    }
    pub fn jmp_tbl(addr: u32, ovl: Option<&BlockName>) -> Self {
        Label::from_kind(addr, ovl, LabelKind::JmpTbl)
    }
    pub fn jmp_target(addr: u32, ovl: Option<&BlockName>) -> Self {
        Label::from_kind(addr, ovl, LabelKind::JmpTarget)
    }
    pub fn data(addr: u32, ovl: Option<&BlockName>) -> Self {
        Label::from_kind(addr, ovl, LabelKind::Data)
    }

    fn from_kind(addr: u32, o: Option<&BlockName>, kind: LabelKind) -> Self {
        Self {
            addr,
            kind,
            location: o.into(),
        }
    }

    /// Ensure that `Label` self is in the proper section; update the label if that is not the case
    pub fn update_kind(&mut self, section: Section) {
        match (section, &self.kind) {
            (Section::Data, LabelKind::Routine) => {
                trace!("{:4}Update label kind to Data: {:x?}", "", &self);
                self.kind = LabelKind::Data;
            }
            (Section::Text, LabelKind::Data) => {
                trace!("{:4}Update label kind to Text: {:x?}", "", &self);
                self.kind = LabelKind::Routine;
            }
            // Data improperly parsed by capstone as a branch instruction
            (Section::Data, LabelKind::Local) => {
                trace!("{:4}Update Local label to Data: {:x?}", "", &self);
                self.kind = LabelKind::Data;
            }
            // Other sections aren't important for updating
            _ => (),
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

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LabelKind::*;
        use LabelLoc::*;

        match self.kind {
            Routine => write!(f, "func"),
            Data => write!(f, "D"),
            JmpTbl => write!(f, "jtbl"),
            JmpTarget => write!(f, "L_JMP"),
            Local => return write!(f, ".L{:08X}", self.addr),
            Named(ref name) => return f.write_str(&name),
        }?;

        // write prefix and address for Routine and Data Labels
        match self.location {
            Overlayed(ref block) => write!(f, "_{}_", block),
            Unspecified => write!(f, "_unspec_"),
            Global => write!(f, "_"),
            NotFound => write!(f, "_NF_"),
            Multiple(..) => write!(f, "_multiple_"),
            UnresolvedMultiple(..) => write!(f, "_unkmulti_"),
        }?;

        write!(f, "{:08X}", self.addr)
    }
}

#[derive(Debug)]
pub struct LabelSet {
    // map from vaddr to label
    pub globals: HashMap<u32, Label>,
    // for easy search later...?
    // base_ovl: HashMap<String, HashMap<u32, Label>>,
    // Map<Overlay Name => Map<Vaddr => Label>>
    pub overlays: HashMap<BlockName, HashMap<u32, Label>>,
}

impl LabelSet {
    pub fn from_config(raw: Vec<RawLabel>, ovls: &HashSet<BlockName>) -> Result<Self, LabelSetErr> {
        let ovl_count = ovls.len();
        // Create maps for global symbols (addr => label)
        // and for overlay specific symbols (overlay => addr => label)
        let mut global_labels = HashMap::new();
        let mut overlays_labels =
            ovls.iter()
                .fold(HashMap::with_capacity(ovl_count), |mut map, ovl| {
                    map.insert(ovl.clone(), HashMap::new());
                    map
                });

        for raw_label in raw {
            match raw_label {
                RawLabel::Global(..) => {
                    let mut label = Label::from(raw_label);
                    label.set_global();
                    global_labels.insert(label.addr, label);
                }
                RawLabel::Overlayed(addr, ref symbol, ref ovl) => {
                    let ovl_str = ovl.as_str();
                    let ovl_labels = overlays_labels.get_mut(ovl_str).ok_or_else(|| {
                        LabelSetErr::UnknownOverlay(addr, symbol.clone(), ovl.clone())
                    })?;
                    let overlay_ref = ovls.get(ovl_str).expect("overlay must exist");
                    let mut label = Label::from(raw_label);
                    label.set_overlay(overlay_ref);
                    ovl_labels.insert(label.addr, label);
                }
            };
        }

        Ok(Self {
            globals: global_labels,
            overlays: overlays_labels,
        })
    }

    /// Get the set of labels for `name`. This will be either a specific set
    /// of overlayed labels or the global set
    pub fn get_block_map(&self, name: &BlockName) -> &HashMap<u32, Label> {
        self.overlays.get(name).unwrap_or(&self.globals)
    }
}

impl fmt::Display for LabelSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Global Labels ({}):", self.globals.len())?;
        for label in self.globals.values() {
            writeln!(f, "{:4}{} << {:x?}", "", &label, &label)?;
        }
        writeln!(f, "Overlayed Labels:")?;
        for (block, set) in &self.overlays {
            writeln!(f, "{:4}{} ({} labels):", "", &block, set.len())?;
            for label in set.values() {
                writeln!(f, "{:8}{} << {:x?}", "", &label, &label)?;
            }
        }

        Ok(())
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
