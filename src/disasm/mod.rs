mod instruction;
mod mipsvals;
mod pass1;

use crate::config::{RawCodeBlock, RawLabel};
use err_derive::Error;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
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

#[derive(Debug, Error)]
pub enum MemoryMapErr {
    #[error(display = "Block at ROM {:#x} has a repeated name <{}>", _1, _0)]
    RepeatedOvlName(Rc<str>, u32),
    #[error(display = "Unknown Overlay \"{}\" in Overlay Set \"{}\"", _1, _0)]
    UnkOvl(String, String),
}

#[derive(Debug)]
pub struct MemoryMap {
    /// sorted map of code sections (based on text start)
    pub blocks: Vec<CodeBlock>,
    /// list of overlays
    pub overlays: HashSet<Overlay>,
    /// set of loaded overlays for a given overlay
    pub overlay_sets: OverlaySet,
}

impl MemoryMap {
    pub fn from_config_parts(
        mut blocks: impl Iterator<Item = CodeBlock>,
        count: usize,
        raw_ovl_sets: HashMap<String, Vec<String>>,
    ) -> Result<Self, MemoryMapErr> {
        let (mut blocks, overlays) = blocks.try_fold(
            (Vec::with_capacity(count), HashSet::with_capacity(count)),
            fold_codeblocks,
        )?;
        // maybe add in BSS sorting? add CMP to BlockRange?
        blocks.sort_unstable_by(|a, b| a.range.ram_start.cmp(&b.range.ram_start));

        let overlay_sets = create_overlay_map(raw_ovl_sets, &overlays)?;

        Ok(Self {
            blocks,
            overlays,
            overlay_sets,
        })
    }
}

type FoldBlockAcc = (Vec<CodeBlock>, HashSet<Overlay>);
fn fold_codeblocks(
    (mut blocks, mut ovls): FoldBlockAcc,
    block: CodeBlock,
) -> Result<FoldBlockAcc, MemoryMapErr> {
    use MemoryMapErr::RepeatedOvlName as Rep;

    match block.kind {
        BlockKind::BaseOverlay | BlockKind::Overlay => {
            let new = ovls.insert(block.name.clone().into());
            if !new {
                return Err(Rep(block.name.clone(), block.range.rom_start));
            }
        }
        BlockKind::Global => (),
    };

    blocks.push(block);

    Ok((blocks, ovls))
}

/// Create a HashMap that links each overlay with all of its possible "paired" overlays.
/// This map thus shows all possible code/data that a given overlay can see.
/// Note that the paired set includes the "main" overlay itself.
fn create_overlay_map(
    sets: HashMap<String, Vec<String>>,
    overlays: &HashSet<Overlay>,
) -> Result<OverlaySet, MemoryMapErr> {
    use MemoryMapErr::UnkOvl;

    let mut map = OverlaySet::with_capacity(overlays.len());
    let mut buffer = Vec::with_capacity(overlays.len());
    for (set_name, overlay_set) in sets {
        for s in overlay_set {
            let ovl = overlays
                .get(s.as_str())
                .ok_or_else(|| UnkOvl(set_name.clone(), s.clone()))?;
            buffer.push(ovl.clone());
        }

        for ovl in buffer.iter().cloned() {
            map.entry(ovl)
                .or_insert_with(|| HashSet::new())
                .extend(buffer.iter().cloned())
        }

        buffer.clear();
    }

    Ok(map)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BlockKind {
    Global,
    BaseOverlay,
    Overlay,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Section {
    Bss,
    TextData,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct BlockRange {
    rom_start: u32,
    rom_end: u32,
    ram_start: u32,
    ram_end: u32,
    bss_start: Option<NonZeroU32>,
    bss_end: Option<NonZeroU32>,
}

impl BlockRange {
    /// get the ROM location and size of the block in the proper numeric types
    /// to use with `io::Read`
    pub fn get_rom_offsets(&self) -> (u64, usize) {
        (
            self.rom_start as u64,
            (self.rom_end - self.rom_start) as usize,
        )
    }

    pub fn get_text_vaddr(&self) -> u32 {
        self.ram_start
    }

    fn contains(&self, addr: u32) -> bool {
        self.section(addr).is_some()
    }

    fn section(&self, addr: u32) -> Option<Section> {
        if self.ram_start <= addr && addr < self.ram_end {
            Some(Section::TextData)
        } else {
            self.bss_start
                .and_then(|s| self.bss_end.map(|e| s.get() <= addr && addr < e.get()))
                .and_then(|r| if r { Some(Section::Bss) } else { None })
        }
    }
}

impl From<(u32, u32, u32)> for BlockRange {
    // from (rom, ram, size)
    fn from(textonly: (u32, u32, u32)) -> Self {
        Self {
            rom_start: textonly.0,
            rom_end: textonly.0 + textonly.2,
            ram_start: textonly.1,
            ram_end: textonly.1 + textonly.2,
            bss_start: None,
            bss_end: None,
        }
    }
}

impl From<(u32, u32, u32, u32, u32)> for BlockRange {
    // from (rom, ram, size, noload, noloadend)
    fn from(full: (u32, u32, u32, u32, u32)) -> Self {
        Self {
            rom_start: full.0,
            rom_end: full.0 + full.2,
            ram_start: full.1,
            ram_end: full.1 + full.2,
            bss_start: NonZeroU32::new(full.3),
            bss_end: NonZeroU32::new(full.4),
        }
    }
}

#[derive(Debug)]
pub struct CodeBlock {
    pub name: Rc<str>,
    pub kind: BlockKind,
    pub range: BlockRange,
}

impl CodeBlock {
    pub fn from_raw(raw: RawCodeBlock, kind: BlockKind) -> Self {
        let (name, range) = match raw {
            RawCodeBlock::MissingNoload(rs, re, n, v) => {
                (Rc::from(n), BlockRange::from((rs, v, re - rs)))
            }
            RawCodeBlock::Noload(rs, re, n, v, bs, be) => {
                (Rc::from(n), BlockRange::from((rs, v, re - rs, bs, be)))
            }
        };

        Self { name, kind, range }
    }
}

#[derive(Debug)]
pub enum LabelKind {
    Local,
    Global,
    Data,
    Named(String),
}

#[derive(Debug)]
pub struct Label {
    addr: u32,
    kind: LabelKind,
    /// None is a global symbol
    overlay: Option<Overlay>,
}

impl Label {
    pub fn add_overlay(&mut self, ovl: &Overlay) {
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
            kind: LabelKind::Global,
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
    overlays: HashMap<Overlay, HashMap<u32, Label>>,
}

impl LabelSet {
    pub fn from_raw_labels(
        raw: Vec<RawLabel>,
        ovls: &HashSet<Overlay>,
    ) -> Result<Self, LabelSetErr> {
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
                        return Err(LabelSetErr::UnknownOverlay(addr, symbol, ovl));
                    }
                    let overlay = Overlay::from(ovl);
                    let kind = LabelKind::Named(symbol);
                    let label = Label {
                        addr,
                        kind,
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
pub enum LabelSetErr {
    #[error(
        display = r#"Overlay "{}" not listed in config overlays, but it was listed as the overlay for label "{}" ({:#08x})"#,
        _2,
        _1,
        _0
    )]
    UnknownOverlay(u32, String, String),
}
