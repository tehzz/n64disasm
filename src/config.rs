use crate::disasm::labels::{LabelSet, LabelSetErr};
use crate::disasm::memmap::{BlockKind, CodeBlock, MemoryMap, MemoryMapErr};
use err_derive::Error;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawCodeBlock {
    // RomStart, RomEnd, Name, Vaddr
    MissingNoload(u32, u32, String, u32),
    // RomStart, RomEnd, Name, Vaddr, BssStart, BssEnd
    Noload(u32, u32, String, u32, u32, u32),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawLabel {
    // addr, label
    Global(u32, String),
    // addr, label, overlay
    Overlayed(u32, String, String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct RawConfig {
    expak: bool,
    static_code: Vec<RawCodeBlock>,
    base_overlays: Vec<RawCodeBlock>,
    overlays: Vec<RawCodeBlock>,
    overlay_sets: HashMap<String, Vec<String>>,
    labels: Vec<RawLabel>,
}

#[derive(Debug)]
pub struct Config {
    /// The collection of code sections (text, data, and bss) mapped based on RAM location
    pub memory: MemoryMap,
    /// Set of labels from config file, sorted into global and overlayed bins
    pub labels: LabelSet,
    /// Does the game use the expansion pak
    pub expak: bool,
}

#[derive(Debug, Error)]
pub enum ConfigParseError {
    #[error(display = "Problem creating memory map from config YAML file")]
    MemMap(#[error(source)] MemoryMapErr),
    #[error(display = "Problem identifying labels in config YAML file")]
    Label(#[error(source)] LabelSetErr),
    #[error(display = "Problem opening config YAML file")]
    Io(#[error(source)] ::std::io::Error),
    #[error(display = "Problem parsing the config YAML file")]
    Serde(#[error(source)] serde_yaml::Error),
}

pub fn parse_config(p: &Path) -> Result<Config, ConfigParseError> {
    let f = File::open(p)?;
    let RawConfig {
        expak,
        static_code,
        base_overlays,
        overlays,
        overlay_sets,
        labels,
    } = serde_yaml::from_reader(f)?;

    let total_blocks = static_code.len() + base_overlays.len() + overlays.len();
    let blocks_iter = make_block_iter(static_code, BlockKind::Global)
        .chain(make_block_iter(base_overlays, BlockKind::BaseOverlay))
        .chain(make_block_iter(overlays, BlockKind::Overlay));

    let memory = MemoryMap::from_config_parts(blocks_iter, total_blocks, overlay_sets)?;
    let labels = LabelSet::from_config(labels, &memory.overlays)?;

    Ok(Config {
        memory,
        labels,
        expak,
    })
}

fn make_block_iter(raw: Vec<RawCodeBlock>, kind: BlockKind) -> impl Iterator<Item = CodeBlock> {
    raw.into_iter().map(move |b| CodeBlock::from_raw(b, kind))
}
