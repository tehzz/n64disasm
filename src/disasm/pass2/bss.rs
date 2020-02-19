use crate::disasm::{labels::Label, memmap::CodeBlock, pass2::Wtr};
use std::io::{self, Write};

const BSS_FILE_PRELUDE: &'static str = include_str!("inc/prelude.bss.s");

/// Write out a block's BSS labels as a GNU as file.
/// Note that the `labels` slice needs to be sorted
pub(super) fn write_block_bss(f: &mut Wtr, labels: &[&Label], block: &CodeBlock) -> io::Result<()> {
    f.write_all(BSS_FILE_PRELUDE.as_bytes())?;

    let mut prior_label: Option<&Label> = None;
    for label in labels {
        if let Some(prior) = prior_label {
            let size = label.addr.saturating_sub(prior.addr);
            assert!(size > 0, "{:08x} - {:08x}", label.addr, prior.addr);
            writeln!(f, "{:4}.space {}", "", size)?;
        }
        writeln!(f, "glabel {}", label)?;
        prior_label = Some(label);
    }

    if let Some(final_label) = prior_label {
        let (_, end) = block.range.get_bss().expect("writing bss");
        let size = end.saturating_sub(final_label.addr);
        assert!(size > 0);
        writeln!(f, "{:4}.space {}", "", size)?;
    }

    Ok(())
}
