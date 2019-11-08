use crate::disasm::{BlockKind, CodeBlock, LabelSet, LabelSetError, Overlay, OverlaySet};
use err_derive::Error;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;

pub type RawCodeBlock = (u32, u32, String, u32);

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawLabel {
    Global(u32, String),
    Overlayed(u32, String, String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct RawConfig {
    static_code: Vec<RawCodeBlock>,
    base_overlays: Vec<RawCodeBlock>,
    overlays: Vec<RawCodeBlock>,
    overlay_sets: HashMap<String, Vec<String>>,
    labels: Vec<RawLabel>,
}

#[derive(Debug)]
pub struct Config {
    /// List of all code sections
    pub blocks: Vec<CodeBlock>,
    /// Set of all overlays
    pub overlays: HashSet<Overlay>,
    // map an overlay to all possible other overlays that could be loaded at the same time
    pub overlay_map: OverlaySet,
    /// Set of labels from config file, sorted into global and overlayed bins
    pub labels: LabelSet,
}

#[derive(Debug, Error)]
pub enum ConfigParseError {
    #[error(display = "Unknown Overlay \"{}\" in Overlay Set \"{}\"", _1, _0)]
    SetUnkOverlay(String, String),
    #[error(display = "Problem identifying labels in config YALM file")]
    Label(#[error(source)] LabelSetError),
    #[error(display = "Problem opening config YAML file")]
    Io(#[error(source)] ::std::io::Error),
    #[error(display = "Problem parsing the config YAML file")]
    Serde(#[error(source)] serde_yaml::Error),
}

pub fn parse_config(p: &Path) -> Result<Config, ConfigParseError> {
    let f = File::open(p)?;
    let RawConfig {
        static_code,
        base_overlays,
        overlays,
        overlay_sets,
        labels,
    } = serde_yaml::from_reader(f)?;

    let total_blocks = static_code.len() + base_overlays.len() + overlays.len();
    let total_overlays = base_overlays.len() + overlays.len();

    let (blocks, overlays) = block_iter(static_code, BlockKind::Global)
        .chain(block_iter(base_overlays, BlockKind::BaseOverlay))
        .chain(block_iter(overlays, BlockKind::Overlay))
        .fold(
            (
                Vec::with_capacity(total_blocks),
                HashSet::with_capacity(total_overlays),
            ),
            |(mut b, mut o), block| {
                match block.kind {
                    BlockKind::BaseOverlay | BlockKind::Overlay => {
                        // TODO: check for duplicate overlays and error
                        o.insert(block.name.clone().into());
                    }
                    BlockKind::Global => (),
                };

                b.push(block);

                (b, o)
            },
        );

    let overlay_map = create_overlay_map(&overlay_sets, &overlays)?;
    let labels = LabelSet::from_raw_labels(labels, &overlays)?;

    let config = Config {
        blocks,
        overlays,
        labels,
        overlay_map,
    };

    Ok(config)
}

fn block_iter(raw: Vec<RawCodeBlock>, kind: BlockKind) -> impl Iterator<Item = CodeBlock> {
    raw.into_iter().map(move |b| CodeBlock::from_raw(b, kind))
}

/// Create a HashMap that links each overlay with all of its possible "paired" overlays.
/// This map thus shows all possible code/data that a given overlay can see.
/// Note that the paired set includes the "main" overlay itself.
fn create_overlay_map(
    sets: &HashMap<String, Vec<String>>,
    overlays: &HashSet<Overlay>,
) -> Result<OverlaySet, ConfigParseError> {
    use ConfigParseError::SetUnkOverlay as UnkOvl;

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
