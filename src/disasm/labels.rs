use crate::boolext::BoolOptionExt;
use crate::config::RawLabel;
use crate::disasm::memmap::{BlockName, Section};
use err_derive::Error;
use log::trace;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;

#[derive(Debug, Error)]
pub enum LabelSetErr {
    #[error(
        display = r#"Overlay "{}" not listed in config overlays, but it was listed as the overlay for label "{}" ({:#08x})"#,
        _2,
        _1,
        _0
    )]
    UnknownOverlay(u32, String, String),
    #[error(display = "Label \"{}\" is not valid for gas label", _0)]
    IllegalLabel(String),
    #[error(display = "Overlay \"{}\" is not valid for gas label", _0)]
    IllegalOvl(String),
}

#[derive(Debug)]
pub struct LabelSet {
    // Map<Vaddr => Label>
    pub globals: HashMap<u32, Label>,
    // Map<Overlay Name => Map<Vaddr => Label>>
    pub overlays: HashMap<BlockName, HashMap<u32, Label>>,
}

#[derive(Debug, Clone)]
pub struct Label {
    pub addr: u32,
    pub kind: LabelKind,
    pub location: LabelLoc,
}

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
                    let mut label = Label::try_from(raw_label)?;
                    label.set_global();
                    global_labels.insert(label.addr, label);
                }
                RawLabel::Overlayed(addr, ref symbol, ref ovl) => {
                    let ovl_str = ovl.as_str();
                    let ovl_labels = overlays_labels.get_mut(ovl_str).ok_or_else(|| {
                        LabelSetErr::UnknownOverlay(addr, symbol.clone(), ovl.clone())
                    })?;
                    let overlay_ref = ovls.get(ovl_str).expect("overlay must exist");
                    let mut label = Label::try_from(raw_label)?;
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

impl TryFrom<RawLabel> for Label {
    type Error = LabelSetErr;
    fn try_from(r: RawLabel) -> Result<Self, Self::Error> {
        use LabelLoc::{Overlayed, Unspecified};
        use LabelSetErr::{IllegalLabel, IllegalOvl};

        let (addr, symbol, location) = match r {
            RawLabel::Global(a, s) => valid_gas_label(&s)
                .b_then(())
                .ok_or_else(|| IllegalLabel(s.clone()))
                .map(|_| (a, s, Unspecified)),
            RawLabel::Overlayed(a, s, o) => {
                let lres = valid_gas_label(&s)
                    .b_then(())
                    .ok_or_else(|| IllegalLabel(s.clone()));
                let ores = valid_gas_overlay(&o)
                    .b_then(())
                    .ok_or_else(|| IllegalOvl(o.clone()));
                lres.and(ores).map(|_| (a, s, Overlayed(o.into())))
            }
        }?;
        let kind = LabelKind::Named(symbol);

        Ok(Self {
            addr,
            kind,
            location,
        })
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
            JmpTarget => write!(f, "jtgt"),
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

/// [From the GNU as manual](https://sourceware.org/binutils/docs/as/Symbol-Names.html)
/// > Symbol names begin with a letter or with one of ‘._’.
/// > On most machines, you can also use $ in symbol names; exceptions are noted in Machine Dependencies.
/// > That character may be followed by any string of digits, letters, dollar signs
/// > (unless otherwise noted for a particular target machine), and underscores.
/// > Generating a multibyte symbol name from a label is not currently supported.
fn valid_gas_label(s: &str) -> bool {
    let mut chars = s.chars();

    chars.next().map_or(false, check_start_char) && check_label_tail(chars)
}
/// since the overlay name will become part of the label,
/// it has to follow the not-leading-character label restrictions
fn valid_gas_overlay(s: &str) -> bool {
    check_label_tail(s.chars())
}

fn check_start_char(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '.'
}

fn check_label_tail(mut s_iter: impl Iterator<Item = char>) -> bool {
    s_iter.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

#[cfg(test)]
mod test {
    use super::*;

    const VALID_LABELS: &[&str] = &[
        "snake_case_1",
        "camelCase",
        "camelCase0x165",
        "PascalCase",
        "with$char",
        ".local",
        ".Local",
        "Local",
    ];

    const INVALID_LABELS: &[&str] = &[
        "1_numeric_start",
        "100",
        "internal-dash",
        "-leadDash",
        "internal.dot",
        "label?",
        "?label¿",
        "multibyte🤬 🤡",
        "über-lead",
    ];

    #[test]
    fn check_valid_gas_labels() {
        for label in VALID_LABELS.iter() {
            assert!(
                valid_gas_label(label),
                "Valid GAS label {} marked as invalid",
                label
            );
        }
    }

    #[test]
    fn check_invalid_gas_labels() {
        for label in INVALID_LABELS.iter() {
            assert!(
                !valid_gas_label(label),
                "Invalid GAS label {} marked as valid",
                label
            );
        }
    }
}
