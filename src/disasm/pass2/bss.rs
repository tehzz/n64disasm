use crate::disasm::{
    labels::{Label, LabelKind},
    memmap::{CodeBlock, Section},
    pass2::Wtr,
};
use std::collections::HashMap;
use std::io::{self, Write};

const BSS_FILE_PRELUDE: &'static str = include_str!("inc/prelude.bss.s");

pub(super) fn write_block_bss(
    f: &mut Wtr,
    labels: &HashMap<u32, Label>,
    block: &CodeBlock,
) -> io::Result<()> {
    let is_data = |(_, l): &(&u32, &Label)| l.kind == LabelKind::Data;
    // this will only return valid labels for this block
    let is_bss = |(&a, _): &(&u32, &Label)| {
        block
            .range
            .section(a)
            .map(|s| s == Section::Bss)
            .unwrap_or(false)
    };
    // TODO: Vec<&Labels> only?
    let bss_labels = {
        let mut v: Vec<(u32, &Label)> = labels
            .iter()
            .filter(is_data)
            .filter(is_bss)
            .map(|(a, l)| (*a, l))
            .collect();
        v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        v
    };

    f.write_all(BSS_FILE_PRELUDE.as_bytes())?;

    let mut prior = None;
    for (addr, label) in bss_labels {
        if let Some(prior_addr) = prior {
            let size = addr.saturating_sub(prior_addr);
            assert!(size > 0, "{:08x} - {:08x}", addr, prior_addr);
            writeln!(f, "{:4}.space {}", "", size)?;
        }
        writeln!(f, "glabel {}", label)?;
        prior = Some(addr);
    }

    if let Some(final_addr) = prior {
        let (_, end) = block.range.get_bss().expect("writing bss");
        let size = end.saturating_sub(final_addr);
        assert!(size > 0);
        writeln!(f, "{:4}.space {}", "", size)?;
    }

    Ok(())
}
