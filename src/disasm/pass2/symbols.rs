use crate::disasm::{
    labels::{Label, LabelLoc},
    memmap::BlockRange,
    pass1::{BlockInsn, LabelPlace},
    pass2::{self, Memory, Wtr},
};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

pub(super) fn write_symbols<'a, F>(
    block: &'a BlockInsn,
    block_range: &BlockRange,
    mem: &'a Memory,
    make_file: F,
) -> io::Result<()>
where
    F: Fn(&'a str) -> io::Result<Wtr>,
{
    let find_label = |addr| pass2::find_label(mem, block, addr);

    if let Some(unres_syms) = block.unresolved_labels.as_ref() {
        let mut outfile = make_file(".unresolved.ld")?;
        write_unresolved(&mut outfile, &block.name, unres_syms, mem)?;
    }

    write_external(block, block_range, find_label, make_file)
}

fn write_unresolved(
    f: &mut Wtr,
    name: &str,
    syms: &HashMap<u32, Label>,
    mem: &Memory,
) -> io::Result<()> {
    use LabelLoc::*;

    let find_label_in_ovl = |ovl, addr| mem.label_set.overlays[ovl].get(&addr);

    let mut sorted_syms = syms.values().collect::<Vec<_>>();
    sorted_syms.sort_unstable_by(pass2::lower_addr);

    writeln!(
        f,
        "/* Symbols in \"{}\" that are in multiple locations */",
        name
    )?;
    for s in sorted_syms {
        write!(f, "{:4}{} = {:#08X}; ", "", s, s.addr)?;
        let mut comma = "";
        match s.location {
            Multiple(ref blocks) => {
                write!(f, "/* could be: ")?;
                blocks
                    .iter()
                    .filter_map(|o| find_label_in_ovl(o, s.addr))
                    .try_for_each(|l| write_locations(f, &mut comma, l))
            }
            UnresolvedMultiple(ref blocks) => {
                write!(f, "/* in ")?;
                blocks
                    .iter()
                    .try_for_each(|o| write_locations(f, &mut comma, o))
            }
            Global | Overlayed(..) | NotFound | Unspecified => {
                unreachable!("symbol should be unresolved")
            }
        }?;
        writeln!(f, " */")?;
    }

    Ok(())
}

fn write_locations<T: std::fmt::Display>(f: &mut Wtr, comma: &mut &str, loc: T) -> io::Result<()> {
    write!(f, "{}{}", comma, loc).map(|_| *comma = ", ")
}

type Sorted<'a> = BTreeMap<u32, &'a Label>;
#[derive(Debug, Default)]
struct SortedAcc<'a> {
    ovl: BTreeMap<&'a str, Sorted<'a>>,
    g: Sorted<'a>,
}

impl<'a> SortedAcc<'a> {
    fn is_empty(&self) -> bool {
        self.ovl.len() == 0 && self.g.len() == 0
    }
}

fn write_external<'a, F, G>(
    block: &BlockInsn,
    range: &BlockRange,
    find_label: F,
    make_file: G,
) -> io::Result<()>
where
    F: Fn(u32) -> Option<&'a Label>,
    G: Fn(&'a str) -> io::Result<Wtr>,
{
    use LabelLoc as L;
    use LabelPlace as P;

    let sorted = block
        .label_locations
        .iter()
        .filter_map(|(&addr, loc)| match loc {
            P::External(..) => find_label(addr),
            P::Global if !range.contains(addr) => find_label(addr),
            P::Global => None,
            P::Internal | P::NotFound | P::MultipleExtern | P::Hardware => None,
        })
        .fold(SortedAcc::default(), |mut acc, label| {
            match label.location {
                L::Global => acc.g.insert(label.addr, label),
                L::Overlayed(ref ovl) => acc
                    .ovl
                    .entry(&*ovl)
                    .or_insert_with(Sorted::new)
                    .insert(label.addr, label),
                _ => unreachable!(),
            };

            acc
        });

    if sorted.is_empty() {
        return Ok(());
    }

    let mut out = make_file(".extern.ld")?;
    if !sorted.g.is_empty() {
        write_extern_globals(&mut out, &sorted, &block.name)?;
    }

    if !sorted.ovl.is_empty() {
        write_extern_overlayed(&mut out, &sorted, &block.name)?;
    }

    Ok(())
}

fn write_extern_globals(f: &mut Wtr, sorted: &SortedAcc<'_>, name: &str) -> io::Result<()> {
    writeln!(f, "/* External Global Symbols in {} */", name)?;
    for (addr, label) in sorted.g.iter() {
        writeln!(f, "{:4}{} = {:#08X};", "", label, addr)?;
    }
    writeln!(f)?;

    Ok(())
}

fn write_extern_overlayed(f: &mut Wtr, sorted: &SortedAcc<'_>, name: &str) -> io::Result<()> {
    writeln!(f, "/* External Overlayed Symbols in {} */", name)?;

    for (ovl, labels) in sorted.ovl.iter() {
        writeln!(f, "/* {} */", ovl)?;
        for (addr, label) in labels.iter() {
            writeln!(f, "{:4}{} = {:#08X};", "", label, addr)?;
        }
        writeln!(f)?;
    }

    Ok(())
}
