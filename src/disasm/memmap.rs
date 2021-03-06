use crate::config::RawCodeBlock;
use crate::disasm::{hwreg::N64_HW_REG_MAP, labels::Label};
use err_derive::Error;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::ops::Deref;
use std::sync::Arc;

/// A wrapper struct for a code block's name
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockName(Arc<str>);

impl Deref for BlockName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for BlockName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for BlockName {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl Into<String> for BlockName {
    fn into(self) -> String {
        (*self.0).into()
    }
}

impl Borrow<str> for BlockName {
    fn borrow(&self) -> &str {
        Borrow::borrow(&self.0)
    }
}

impl AsRef<str> for BlockName {
    fn as_ref(&self) -> &str {
        AsRef::as_ref(&self.0)
    }
}

/// Type alias for a set that goes from an overlay name to a set of all other
/// overlays that could possibly be loaded with that overlay.
pub type OverlaySet = HashMap<BlockName, HashSet<BlockName>>;

#[derive(Debug, Error)]
pub enum MemoryMapErr {
    #[error(display = "Block at ROM {:#x} has a repeated name <{}>", _1, _0)]
    RepeatedOvlName(String, u32),
    #[error(display = "Unknown Overlay \"{}\" in Overlay Set \"{}\"", _1, _0)]
    UnkOvl(String, String),
}

#[derive(Debug)]
pub struct MemoryMap {
    pub blocks: Vec<CodeBlock>,
    /// list of overlays
    pub overlays: HashSet<BlockName>,
    /// set of loaded overlays for a given overlay
    pub overlay_sets: OverlaySet,
    /// Lookup for address to hardware register label
    pub hardware: &'static HashMap<u32, Label>,
    /// A cache of offsets into `blocks` for overlayed code (based on `overlay_sets`)
    /// So, Overlay => [Idx of Possible Loaded Other Overlays]
    overlay_set_cache: HashMap<BlockName, Vec<usize>>,
    /// Map between block name and index of `blocks` array
    block_map: HashMap<BlockName, usize>,
    /// Cache of all global/always loaded static block indices into `blocks` array
    static_blocks: Vec<usize>,
}

impl MemoryMap {
    /// Convert the raw config entries into a coherent map of memory.
    pub fn from_config_parts(
        mut blocks: impl Iterator<Item = CodeBlock>,
        count: usize,
        raw_ovl_sets: HashMap<String, Vec<String>>,
    ) -> Result<Self, MemoryMapErr> {
        let parsed_config = blocks.try_fold(FoldBlockAcc::with_cap(count), fold_codeblocks)?;
        // maybe add in BSS sorting? add CMP to BlockRange?
        //parsed_config.blocks.sort_unstable_by(|a, b| a.range.ram_start.cmp(&b.range.ram_start));

        let base_ovl_to_dyn_ovl = create_base_ovl_set(&parsed_config);
        let overlay_sets = create_overlay_map(raw_ovl_sets, &base_ovl_to_dyn_ovl, &parsed_config)?;
        let overlay_set_cache = cache_overlay_blocks(&overlay_sets, &parsed_config);
        let hardware = &N64_HW_REG_MAP;

        let FoldBlockAcc {
            blocks,
            overlays,
            block_map,
            ..
        } = parsed_config;

        let static_blocks = blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| b.kind == BlockKind::Global)
            .map(|(i, _)| i)
            .collect();

        Ok(Self {
            blocks,
            overlays,
            overlay_sets,
            overlay_set_cache,
            block_map,
            static_blocks,
            hardware,
        })
    }

    pub fn get_addr_location(&self, addr: u32, block: &str) -> AddrLocation {
        let hits: Vec<BlockName> = if let Some(cached_idx) = self.overlay_set_cache.get(block) {
            self.iter_set_blocks(&cached_idx)
                .chain(self.iter_static_blocks())
                .filter(|block| block.range.contains(addr))
                .map(|block| block.name.clone())
                .collect()
        } else {
            // This addr comes from a block that was not in an overlay set
            // so, the address probably originates in a static block. It could call anywhere...
            self.blocks
                .iter()
                .filter(|block| block.range.contains(addr))
                .map(|block| block.name.clone())
                .collect()
        };

        // The hardware registers should not map to any known code memory region
        // so, explicitly check for the register
        if hits.is_empty() && self.hardware.contains_key(&addr) {
            AddrLocation::Hardware
        } else {
            AddrLocation::from(hits)
        }
    }

    pub fn get_block(&self, name: &BlockName) -> Option<&CodeBlock> {
        self.block_map.get(name).map(move |&i| &self.blocks[i])
    }

    /// Convert a slice of indices from `overlay_set_cache` into an iterator
    /// of that overlay set's code blocks
    fn iter_set_blocks<'m>(
        &'m self,
        block_idx: &'m [usize],
    ) -> impl Iterator<Item = &CodeBlock> + 'm {
        block_idx.iter().copied().map(move |i| &self.blocks[i])
    }
    /// An iterator over just the static/always loaded blocks in this memory map
    fn iter_static_blocks<'m>(&'m self) -> impl Iterator<Item = &CodeBlock> + 'm {
        self.static_blocks
            .iter()
            .copied()
            .map(move |i| &self.blocks[i])
    }
}

#[derive(Debug)]
pub enum AddrLocation {
    NotFound,
    Hardware,
    Single(BlockName),
    Multiple(Vec<BlockName>),
}

impl From<Vec<BlockName>> for AddrLocation {
    fn from(mut hits: Vec<BlockName>) -> Self {
        match hits.len() {
            0 => Self::NotFound,
            1 => Self::Single(hits.pop().unwrap()),
            _ => Self::Multiple(hits),
        }
    }
}

#[derive(Debug)]
pub struct CodeBlock {
    pub name: BlockName,
    pub kind: BlockKind,
    pub range: BlockRange,
}

impl CodeBlock {
    pub fn from_raw(raw: RawCodeBlock, kind: BlockKind) -> Self {
        let (name, range) = match raw {
            RawCodeBlock::MissingNoload(rs, re, n, v) => {
                (BlockName::from(n), BlockRange::from((rs, v, re - rs)))
            }
            RawCodeBlock::Noload(rs, re, n, v, bs, be) => (
                BlockName::from(n),
                BlockRange::from((rs, v, re - rs, bs, be)),
            ),
        };

        Self { name, kind, range }
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.range.intersects(&other.range)
    }
}

struct FoldBlockAcc {
    blocks: Vec<CodeBlock>,
    base_ovls: Vec<BlockName>,
    block_map: HashMap<BlockName, usize>,
    overlays: HashSet<BlockName>,
}
impl FoldBlockAcc {
    fn with_cap(cap: usize) -> Self {
        Self {
            blocks: Vec::with_capacity(cap),
            base_ovls: Vec::with_capacity(cap),
            block_map: HashMap::with_capacity(cap),
            overlays: HashSet::with_capacity(cap),
        }
    }
    fn name_to_block_idx(&self, n: &BlockName) -> Option<usize> {
        self.block_map.get(n).copied()
    }
    fn name_to_block(&self, n: &BlockName) -> Option<&CodeBlock> {
        self.name_to_block_idx(n).map(|i| &self.blocks[i])
    }
}
fn fold_codeblocks(mut acc: FoldBlockAcc, block: CodeBlock) -> Result<FoldBlockAcc, MemoryMapErr> {
    use MemoryMapErr::RepeatedOvlName as Rep;

    match block.kind {
        BlockKind::Overlay => {
            let new = acc.overlays.insert(block.name.clone());
            if !new {
                return Err(Rep(block.name.into(), block.range.rom_start));
            }
        }
        BlockKind::BaseOverlay => {
            let new = acc.overlays.insert(block.name.clone());
            if !new {
                return Err(Rep(block.name.into(), block.range.rom_start));
            }
            acc.base_ovls.push(block.name.clone())
        }
        BlockKind::Global => (),
    };

    acc.blocks.push(block);
    let block_idx = acc.blocks.len() - 1;
    let block_name = acc.blocks.last().unwrap().name.clone();
    acc.block_map.insert(block_name, block_idx);

    Ok(acc)
}

/// While the base overlays are loaded before loading the first set, sometimes a base overlay's memory
/// can be overlayed by another overlay. (Persumably the base overlay is then reloaded if needed)
/// This method creates a set of all other possible valid overlays with a given base overlay
fn create_base_ovl_set(info: &FoldBlockAcc) -> OverlaySet {
    use BlockKind::*;

    info.base_ovls
        .iter()
        .map(|base| {
            let base_block = info
                .name_to_block(base)
                .expect("Base overlay is already a known valid code block");

            (
                base.clone(),
                info.blocks
                    .iter()
                    .filter(|block| block.kind == Overlay || block.kind == BaseOverlay)
                    .filter(|block| !block.intersects(base_block))
                    .map(|block| block.name.clone())
                    .collect(),
            )
        })
        .collect()
}

/// Create a HashMap that links each overlay with all of its possible "paired" overlays.
/// This map thus shows all possible code/data that a given overlay can see.
/// Note that the paired set includes the "main" overlay itself.
fn create_overlay_map(
    sets: HashMap<String, Vec<String>>,
    base_to_dyn_overlays: &OverlaySet,
    info: &FoldBlockAcc,
) -> Result<OverlaySet, MemoryMapErr> {
    use MemoryMapErr::UnkOvl;

    let ovl_count = info.overlays.len();

    let mut map = OverlaySet::with_capacity(ovl_count);
    // buffer of overlay names in a given overlay set from the config
    let mut buffer: Vec<&BlockName> = Vec::with_capacity(ovl_count);
    for (set_name, overlay_set) in sets {
        for s in overlay_set {
            let ovl = info
                .overlays
                .get(s.as_str())
                .ok_or_else(|| UnkOvl(set_name.clone(), s.clone()))?;

            buffer.push(ovl);
        }

        let valid_base_overlays = base_to_dyn_overlays
            .iter()
            .filter(|(_, valids)| buffer.iter().all(|ovl| valids.contains(*ovl)))
            .map(|(name, _)| name)
            .collect::<Vec<&BlockName>>();

        for &ovl in &buffer {
            let base_overlays = valid_base_overlays.iter().map(|&b| b.clone());
            let paired_overlays = buffer.iter().map(|&o| o.clone()).chain(base_overlays);

            map.entry(ovl.clone())
                .or_insert_with(HashSet::new)
                .extend(paired_overlays)
        }

        buffer.clear();
    }

    Ok(map)
}

/// Store a set of overlay `BlockName` to indices into the `CodeBlock` array
fn cache_overlay_blocks(sets: &OverlaySet, info: &FoldBlockAcc) -> HashMap<BlockName, Vec<usize>> {
    let get_block_offset = |n| info.name_to_block_idx(n);

    sets.iter()
        .map(|(name, set)| {
            (
                name.clone(),
                set.iter().filter_map(get_block_offset).collect(),
            )
        })
        .collect()
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
    /// Could be in either section, aka not noload
    TextData,
    Text,
    Data,
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
    pub fn get_rom_offsets(&self) -> (usize, usize) {
        (self.rom_start as usize, self.rom_end as usize)
    }

    pub fn get_ram_start(&self) -> u32 {
        self.ram_start
    }

    pub fn get_ram_end(&self) -> u32 {
        self.ram_end
    }

    pub fn contains(&self, addr: u32) -> bool {
        self.section(addr).is_some()
    }
    /// `addr` is in a load (.text or .data) section (not .bss)
    pub fn load_contains(&self, addr: u32) -> bool {
        self.section(addr).map_or(false, |s| s == Section::TextData)
    }

    pub fn get_bss(&self) -> Option<(u32, u32)> {
        self.bss_start
            .and_then(|s| self.bss_end.map(|e| (s.get(), e.get())))
    }

    pub fn section(&self, addr: u32) -> Option<Section> {
        if self.ram_start <= addr && addr < self.ram_end {
            Some(Section::TextData)
        } else {
            self.bss_start
                .and_then(|s| self.bss_end.map(|e| s.get() <= addr && addr < e.get()))
                .and_then(|r| if r { Some(Section::Bss) } else { None })
        }
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.contains(other.ram_start)
            || self.contains(other.ram_end - 1)
            || other
                .bss_start
                .map(|a| self.contains(a.get()))
                .unwrap_or(false)
            || other
                .bss_end
                .map(|a| self.contains(a.get() - 1))
                .unwrap_or(false)
    }
}

impl From<(u32, u32, u32)> for BlockRange {
    // from (rom, ram, size) for converting from config file
    fn from(textonly: (u32, u32, u32)) -> Self {
        assert!(textonly.2 > 0);

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
    // from (rom, ram, size, noload, noloadend) for converting from config file
    fn from(full: (u32, u32, u32, u32, u32)) -> Self {
        assert!(full.3 < full.4);

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn non_intersecting_blocks() {
        let block1 = BlockRange::from((0, 0x00, 0x400));
        let block2 = BlockRange::from((0, 0x400, 0x1000));

        assert!(
            !block1.intersects(&block2) && !block2.intersects(&block1),
            "Blocks should not intersect even if one ends where another begins"
        );

        let block1bss = BlockRange::from((0, 0x00, 0x400, 0x2000, 0x2200));
        let block2bss = BlockRange::from((0, 0x400, 0x1000, 0x2200, 0x22A0));

        assert!(
            !block1bss.intersects(&block2bss) && !block2bss.intersects(&block1bss),
            "Blocks including BSS should not intersect even if one ends where another begins"
        );

        let b1bsstext = BlockRange::from((0x43220, 0x800C7840, 0xEA70, 0x800D62B0, 0x800D6490));
        let b2bsstext = BlockRange::from((0x51C90, 0x800D6490, 0x5A8B0, 0x80130D40, 0x80131B00));

        assert!(
            !b1bsstext.intersects(&b2bsstext) && !b2bsstext.intersects(&b1bsstext),
            "Blocks whose BSS ends where the next block's text begin should not intersect"
        );
    }
    #[test]
    fn intersecting_blocks() {
        let block1 = BlockRange::from((0, 0x00, 0x400));
        let block2 = BlockRange::from((0, 0x200, 0x1000));

        assert!(
            block1.intersects(&block2) && block2.intersects(&block1),
            "Blocks with overlapping RAM areas should intersect"
        );

        let block1bss = BlockRange::from((0, 0x00, 0x400, 0x2000, 0x2200));
        let block2bss = BlockRange::from((0, 0x400, 0x1000, 0x2000, 0x22A0));

        assert!(
            block1bss.intersects(&block2bss) && block2bss.intersects(&block1bss),
            "Blocks with overlapping BSS areas should intersect"
        );
    }
    #[test]
    #[should_panic]
    fn panic_on_zero_sized_ram_range() {
        BlockRange::from((0, 0x100, 0x000));
    }
    #[test]
    #[should_panic]
    fn panic_on_negative_bss_range() {
        BlockRange::from((0, 0x00, 0x400, 0x100, 0x080));
    }
}
