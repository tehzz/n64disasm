use crate::disasm::{
    labels::Label,
    memmap::BlockName,
    pass1::{BlockInsn, BlockLoadedSections, DataEntry, LoadSectionInfo, ParsedData},
    pass2::{self, Memory, Wtr},
};
use err_derive::Error;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io::{self, Write};
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Debug, Error)]
pub enum DataWriteErr {
    #[error(display = "Pair at {:x} not found in any section", _0)]
    NoSec(u32),
    #[error(display = "Improper data labels: {:08X} before {:08X}", _0, _1)]
    BadPair(u32, u32),
    #[error(display = "Data @ {:08X} ended after section @ {:08X}", _0, _1)]
    BadEnd(u32, u32),
    #[error(
        display = "Total size was less than size of parsed data: {} - {}",
        _0,
        _1
    )]
    BadSize(u32, u32),
    #[error(display = "Io issue when writing data file")]
    Io(#[error(source)] io::Error),
    #[error(display = "Block name <{}> missing information", _0)]
    NoBlock(BlockName),
}

type DResult<T> = Result<T, DataWriteErr>;
type DataMap<'r> = BTreeMap<u32, DataEntry<'r>>;

const DATA_FILE_PRELUDE: &str = include_str!("inc/prelude.data.s");

pub(super) fn write_block_data(
    f: &mut Wtr,
    raw_bin: &str,
    labels: &[&Label],
    sections: &BlockLoadedSections,
    block: &BlockInsn,
    mem: &Memory,
) -> DResult<()> {
    let block_ram_start = mem
        .memory_map
        .get_block(&block.name)
        .map(|b| b.range.get_ram_start() as u32)
        .ok_or_else(|| DataWriteErr::NoBlock(block.name.clone()))?;
    let block_data = &block.parsed_data;

    let info = OutputInfo {
        raw_bin,
        ram_to_block_idx: block_ram_start,
    };
    let find_label = |addr| pass2::find_label(mem, block, addr);

    f.write_all(DATA_FILE_PRELUDE.as_bytes())?;

    writeln!(f, "# Data Sections")?;
    for sec in sections.as_slice() {
        writeln!(f, "#  {:08X} -> {:08X}", sec.range.start, sec.range.end)?;
    }
    writeln!(f)?;

    let combined = combine_labels_data(labels, block_data);
    combined
        .windows(2)
        .map(|p| TryInto::<&[Paired; 2]>::try_into(p).unwrap())
        .map(|p| size_pair(p, sections))
        .chain(size_final(combined.last(), sections))
        .try_for_each(|sp| write_sized_pair(info, find_label, f, sp))
}

#[derive(Debug, Copy, Clone)]
struct OutputInfo<'a> {
    raw_bin: &'a str,
    ram_to_block_idx: u32,
}

#[derive(Debug, Copy, Clone)]
struct SizedPaired<'a, 'r> {
    paired: Paired<'a, 'r>,
    size: u32,
}

#[derive(Debug, Clone, Copy)]
enum Paired<'a, 'r> {
    Both(&'a Label, &'a DataEntry<'r>),
    OnlyLabel(&'a Label),
    OnlyData(&'a DataEntry<'r>),
}

impl<'a, 'r> Paired<'a, 'r> {
    fn addr(&self) -> u32 {
        match self {
            Self::Both(l, _) => l.addr,
            Self::OnlyLabel(l) => l.addr,
            Self::OnlyData(d) => d.addr,
        }
    }
}

/// calc the size in bytes between where cur is and next while also taking into
/// account breaks between sections
fn size_pair<'a, 'r>(
    [cur, next]: &[Paired<'a, 'r>; 2],
    sections: &BlockLoadedSections,
) -> DResult<SizedPaired<'a, 'r>> {
    use DataWriteErr::{BadEnd, BadPair};

    let cur_sec = get_sec(cur.addr(), sections)?;
    let next_sec = get_sec(next.addr(), sections)?;

    let size = if cur_sec != next_sec {
        diff_size(cur.addr(), cur_sec.range.end, BadEnd)
    } else {
        diff_size(cur.addr(), next.addr(), BadPair)
    }?;

    Ok(SizedPaired { paired: *cur, size })
}

fn size_final<'a, 'r>(
    last: Option<&Paired<'a, 'r>>,
    sections: &BlockLoadedSections,
) -> Option<DResult<SizedPaired<'a, 'r>>> {
    use DataWriteErr::BadEnd;

    last.map(|last| {
        get_sec(last.addr(), sections)
            .and_then(|s| diff_size(last.addr(), s.range.end, BadEnd))
            .map(|size| SizedPaired {
                paired: *last,
                size,
            })
    })
}

fn get_sec(a: u32, s: &BlockLoadedSections) -> DResult<&LoadSectionInfo> {
    s.find_address(a).ok_or_else(|| DataWriteErr::NoSec(a))
}

fn diff_size<F>(a: u32, b: u32, err: F) -> DResult<u32>
where
    F: FnOnce(u32, u32) -> DataWriteErr,
{
    let size = b.saturating_sub(a);
    if size > 0 {
        Ok(size)
    } else {
        Err(err(a, b))
    }
}

fn write_sized_pair<'a, F>(
    info: OutputInfo,
    find_label: F,
    f: &mut Wtr,
    res: DResult<SizedPaired>,
) -> DResult<()>
where
    F: FnOnce(u32) -> Option<&'a Label> + Copy,
{
    let pair = res?;
    let block_offset = pair.paired.addr() - info.ram_to_block_idx;
    match pair.paired {
        Paired::OnlyLabel(l) => {
            write_glabel(f, l)?;
            write_incbin(f, info, block_offset, pair.size)?;
        }
        Paired::OnlyData(d) => {
            write_parsed_data(f, d, find_label, pair.size, block_offset, info)?;
        }
        Paired::Both(l, d) => {
            write_glabel(f, l)?;
            write_parsed_data(f, d, find_label, pair.size, block_offset, info)?;
        }
    };

    Ok(())
}

fn write_glabel(f: &mut Wtr, label: &Label) -> io::Result<()> {
    writeln!(f)?;
    writeln!(f, "glabel {}", label)
}

fn write_incbin(f: &mut Wtr, info: OutputInfo, offset: u32, size: u32) -> io::Result<()> {
    writeln!(
        f,
        "{:2}.incbin \"{}\", {:#06X}, {:#X}",
        "", info.raw_bin, offset, size
    )
}

fn write_parsed_data<'a, F>(
    f: &mut Wtr,
    data: &DataEntry,
    fl: F,
    total_size: u32,
    block_offset: u32,
    info: OutputInfo,
) -> DResult<()>
where
    F: FnOnce(u32) -> Option<&'a Label> + Copy,
{
    use DataWriteErr::BadSize;

    let data_size = data.byte_size() as u32;
    let (bytes_left, overflow) = total_size.overflowing_sub(data_size);

    match (overflow, is_asciz(data)) {
        (false, _) => (),
        (true, false) => return Err(BadSize(total_size, data_size)),
        (true, true) => {
            writeln!(f, "# ERROR Misparsed ASCII @ {:06X} in block", block_offset)?;
            write_incbin(f, info, block_offset, total_size)?;
            return Ok(());
        }
    };

    write_data_entry(f, fl, block_offset, data)?;
    if bytes_left > 0 {
        write_incbin(f, info, block_offset + data_size, bytes_left)?;
    }
    Ok(())
}

fn is_asciz(entry: &DataEntry) -> bool {
    match entry.data {
        ParsedData::Asciz(..) => true,
        _ => false,
    }
}

fn write_data_entry<'a, F>(
    f: &mut Wtr,
    find_label: F,
    block_offset: u32,
    entry: &DataEntry,
) -> io::Result<()>
where
    F: FnOnce(u32) -> Option<&'a Label> + Copy,
{
    use ParsedData::*;

    write!(
        f,
        "{:2}/* {:06X} {:08X} */{:2}",
        "", block_offset, entry.addr, ""
    )?;
    match entry.data {
        Float(..) => write!(f, ".float {}", entry),
        Double(..) => write!(f, ".double {}", entry),
        Asciz(s) => write!(f, ".asciz {:?}", s),
        Ptr(ptr) => find_label(ptr)
            .map(|l| write!(f, ".4byte {}", l))
            .unwrap_or_else(|| write!(f, ".4byte {:#08X} # Error: missing label", ptr)),
        JmpTbl(..) => unreachable!("all jump tables should be converted to pointers"),
    }?;
    writeln!(f)?;

    if is_asciz(entry) {
        writeln!(f, "{:2}{:23}.balign 4", "", "")?;
    }

    Ok(())
}

// take sorted slice of Labels to data, and pair with found parsed data
fn combine_labels_data<'a, 'r>(labels: &[&'a Label], data: &'a DataMap<'r>) -> Vec<Paired<'a, 'r>> {
    let begin_iter = labels.first().map(|f| iter_range_tree(None, Some(f), data));
    let end_iter = labels.last().map(|l| iter_range_tree(Some(l), None, data));
    let middle_iter = labels
        .windows(2)
        .map(TryInto::<[&Label; 2]>::try_into)
        .map(Result::unwrap)
        .flat_map(|[cur, next]| iter_range_tree(Some(cur), Some(next), data));

    match (begin_iter, end_iter) {
        (Some(b), Some(e)) => b.chain(middle_iter).chain(e).collect(),
        (Some(b), None) => b.chain(middle_iter).collect(),
        (None, Some(e)) => middle_iter.chain(e).collect(),
        (None, None) => data.values().map(Paired::OnlyData).collect(),
    }
}

fn pair_cur_label<'a, 'r>(label: &'a Label, tree: &'a DataMap<'r>) -> Paired<'a, 'r> {
    tree.get(&label.addr)
        .map(|found| Paired::Both(label, found))
        .unwrap_or_else(|| Paired::OnlyLabel(label))
}

fn iter_range_tree<'a, 'r>(
    cur: Option<&'a Label>,
    next: Option<&'a Label>,
    tree: &'a DataMap<'r>,
) -> impl Iterator<Item = Paired<'a, 'r>> {
    let r = match (cur, next) {
        (Some(c), Some(n)) => (Excluded(c.addr), Excluded(n.addr)),
        (Some(c), None) => (Excluded(c.addr), Unbounded),
        (None, Some(n)) => (Unbounded, Excluded(n.addr)),
        (None, None) => (Unbounded, Unbounded),
    };

    let initial = cur.map(|c| pair_cur_label(c, tree));

    initial
        .into_iter()
        .chain(tree.range(r).map(|(_k, v)| v).map(Paired::OnlyData))
}
