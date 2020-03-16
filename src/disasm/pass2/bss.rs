use crate::boolext::BoolOptionExt;
use crate::disasm::{labels::Label, memmap::CodeBlock, pass2::Wtr};
use err_derive::Error;
use std::io::Write;

#[derive(Debug, Error)]
pub enum BssWriteErr {
    #[error(display = "Tried to output bss.s for block with no .bss")]
    NoBSS,
    #[error(display = "BSS label unsorted: {:x?} before {:x?}", _0, _1)]
    Unsorted(Label, Label),
    #[error(display = "BSS label after section: {:x?} after {:#x}", _0, _1)]
    End(Label, u32),
    #[error(display = "io issue")]
    Io(#[source] std::io::Error),
}

const BSS_FILE_PRELUDE: &str = include_str!("inc/prelude.bss.s");

/// Write out a block's BSS labels as a gas `.s` file.
/// `labels` slice assumed to be sorted
pub(super) fn write_block_bss(
    f: &mut Wtr,
    labels: &[&Label],
    block: &CodeBlock,
) -> Result<(), BssWriteErr> {
    let (start, end) = block.range.get_bss().ok_or(BssWriteErr::NoBSS)?;

    f.write_all(BSS_FILE_PRELUDE.as_bytes())?;
    writeln!(
        f,
        "# {:#08X} => {:#08X} [{:#x} bytes]",
        start,
        end,
        end - start
    )?;

    let mut prior_label: Option<&Label> = None;
    for label in labels {
        if let Some(prior) = prior_label {
            let size = diff_label_size(label, prior)?;
            writeln!(f, "{:4}.space {}", "", size)?;
        }
        writeln!(f, "glabel {}", label)?;
        prior_label = Some(label);
    }

    if let Some(final_label) = prior_label {
        let size = diff_final_label(final_label, end)?;
        writeln!(f, "{:4}.space {}", "", size)?;
    }

    Ok(())
}

fn diff_label_size(cur: &Label, prior: &Label) -> Result<u32, BssWriteErr> {
    let (size, overflow) = cur.addr.overflowing_sub(prior.addr);

    (!overflow)
        .b_then(size)
        .ok_or_else(|| BssWriteErr::Unsorted(cur.clone(), prior.clone()))
}

fn diff_final_label(l: &Label, end: u32) -> Result<u32, BssWriteErr> {
    let (size, overflow) = end.overflowing_sub(l.addr);

    (!overflow)
        .b_then(size)
        .ok_or_else(|| BssWriteErr::End(l.clone(), end))
}
