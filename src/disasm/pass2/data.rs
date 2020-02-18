use crate::disasm::{
    labels::Label,
    memmap::CodeBlock,
    pass1::{BlockLoadedSections, LoadSectionInfo},
    pass2::Wtr,
};
use err_derive::Error;
use std::io::{self, Write};
use std::path::{Display, Path};

#[derive(Debug, Error)]
pub enum DataWriteErr {
    #[error(display = "Improper labels: {:08X} before {:08X}", _0, _1)]
    BadSize(u32, u32),
    #[error(display = "Label @ {:08X} ended after section @ {:08X}", _0, _1)]
    BadEnd(u32, u32),
    #[error(display = "Final label was not in data section: {:?}", _0)]
    BadLast(Label),
    #[error(display = "Io issue when writing data file")]
    Io(#[error(source)] io::Error),
}

type DResult<T> = Result<T, DataWriteErr>;

const DATA_FILE_PRELUDE: &'static str = include_str!("inc/prelude.data.s");

pub(crate) fn write_block_data(
    f: &mut Wtr,
    raw_bin: &Path,
    labels: &[Label],
    sections: BlockLoadedSections,
    block: &CodeBlock,
) -> DResult<()> {
    use DataWriteErr::BadLast;
    let offset = block.range.get_text_vaddr() - block.range.get_rom_offsets().0 as u32;
    let raw_bin = raw_bin.display();

    f.write_all(DATA_FILE_PRELUDE.as_bytes())?;

    writeln!(f, "# Data Sections")?;
    for sec in sections.as_slice() {
        writeln!(f, "#  {:08X} -> {:08X}", sec.range.start, sec.range.end)?;
    }
    writeln!(f, "")?;

    labels
        .iter()
        .filter_map(|label| sections.find_address(label.addr).map(|sec| (label, sec)))
        .scan(LabelWindow::Start, window_labels)
        .filter_map(size_labels)
        .try_for_each(|res| write_data_label(f, offset, &raw_bin, res))?;

    // write final label
    if let Some(last) = labels.last() {
        let sec = sections
            .find_address(last.addr)
            .ok_or_else(|| BadLast(last.clone()))?;
        let res = label_end_diff(last, sec.range.end).map(|size| (last, size));

        write_data_label(f, offset, &raw_bin, res)?;
    }

    Ok(())
}

fn window_labels<'a>(
    state: &mut LabelWindow<'a>,
    (label, section): (&'a Label, &'a LoadSectionInfo),
) -> Option<LabelPair<'a>> {
    use LabelPair::*;
    use LabelWindow::*;

    let combined = match state {
        Start => Empty,
        Prior(prior_l, prior_sec) => {
            if prior_sec != &section {
                EndSec(prior_l, prior_sec.range.end)
            } else {
                Labels(prior_l, label)
            }
        }
    };

    *state = Prior(label, section);

    Some(combined)
}

fn size_labels(pair: LabelPair<'_>) -> Option<DResult<(&Label, u32)>> {
    use LabelPair::*;

    match pair {
        Empty => None,
        Labels(l1, l2) => Some(label_size_diff(l1, l2).map(|s| (l1, s))),
        EndSec(l, end) => Some(label_end_diff(l, end).map(|s| (l, s))),
    }
}

fn write_data_label(
    f: &mut Wtr,
    offset: u32,
    file: &Display,
    res: DResult<(&Label, u32)>,
) -> DResult<()> {
    let (label, size) = res?;
    let bin_addr = label.addr - offset;
    writeln!(f, "glabel {}", label)?;
    writeln!(
        f,
        "{:4}.incbin \"{}\", {:#06X}, {:#X}",
        "", file, bin_addr, size
    )?;

    Ok(())
}

#[derive(Debug, Copy, Clone)]
enum LabelWindow<'a> {
    Start,
    Prior(&'a Label, &'a LoadSectionInfo),
}

#[derive(Debug, Copy, Clone)]
enum LabelPair<'a> {
    Empty,
    Labels(&'a Label, &'a Label),
    EndSec(&'a Label, u32),
}

fn label_size_diff(earlier: &Label, later: &Label) -> Result<u32, DataWriteErr> {
    use DataWriteErr::BadSize;

    let size = later.addr.saturating_sub(earlier.addr);
    if size > 0 {
        Ok(size)
    } else {
        Err(BadSize(earlier.addr, later.addr))
    }
}

fn label_end_diff(label: &Label, end: u32) -> Result<u32, DataWriteErr> {
    use DataWriteErr::BadEnd;

    let size = end.saturating_sub(label.addr);
    if size > 0 {
        Ok(size)
    } else {
        Err(BadEnd(label.addr, end))
    }
}
