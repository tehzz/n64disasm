use crate::disasm::{
    labels::{Label, LabelLoc},
    pass1::BlockInsn,
    pass2::{self, Memory, Wtr},
};
use std::collections::HashMap;
use std::io::{self, Write};

pub(super) fn write_symbols<'a, F>(block: &BlockInsn, mem: &Memory, make_file: F) -> io::Result<()>
where
    F: Fn(&'a str) -> io::Result<Wtr>,
{
    //let find_label = |addr| pass2::find_label(mem, block, addr);
    if let Some(unres_syms) = block.unresolved_labels.as_ref() {
        let mut outfile = make_file(".unresolved.ld")?;
        write_unresolved(&mut outfile, &block.name, unres_syms, mem)?;
    }

    Ok(())
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
        write!(f, "{:4}{} = {:#08X}", "", s, s.addr)?;
        let mut comma = "";
        match s.location {
            Multiple(ref blocks) => {
                write!(f, " /* could be: ")?;
                blocks
                    .iter()
                    .filter_map(|o| find_label_in_ovl(o, s.addr))
                    .try_for_each(|l| write_locations(f, &mut comma, l))
            }
            UnresolvedMultiple(ref blocks) => {
                write!(f, " /* in ")?;
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
