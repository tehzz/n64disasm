mod bss;
mod data;
mod text;

use crate::disasm::{
    labels::{Label, LabelSet},
    memmap::{BlockName, CodeBlock, MemoryMap, Section},
    pass1::{BlockInsn, LabelPlace, Pass1},
};
use err_derive::Error;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use data::DataWriteErr;
use text::AsmWriteError;

#[derive(Debug, Error)]
pub enum Pass2Error {
    #[error(display = "Unable to create output directory for {}", _0)]
    BlockOut(BlockName, #[error(source)] io::Error),
    #[error(display = "Unable to write macro.inc file")]
    MacroInc(#[error(source, no_from)] io::Error),
    #[error(display = "Unable to write not-found-sym.ld file")]
    NFSym(#[error(source, no_from)] io::Error),
    #[error(display = "Io issue")]
    Io(#[error(source)] io::Error),
    #[error(display = "Block name <{}> missing information", _0)]
    NoBlockInfo(BlockName),
    #[error(display = "Unable to disassemble asm for {}", _0)]
    AsmError(BlockName, #[error(source)] AsmWriteError),
    #[error(display = "Unable to output data for {}", _0)]
    DataError(BlockName, #[error(source)] DataWriteErr),
}

type P2Result<T> = Result<T, Pass2Error>;
type Wtr = BufWriter<File>;

const ASM_INCLUDE_MACROS: &'static str = include_str!("pass2/inc/macros.inc");

struct Memory {
    memory_map: MemoryMap,
    label_set: LabelSet,
    not_found_labels: HashMap<u32, Label>,
}

pub fn pass2(p1result: Pass1, rom: &[u8], out: &Path) -> P2Result<()> {
    use Pass2Error as E;

    let Pass1 {
        memory_map,
        labels: label_set,
        blocks,
        not_found_labels,
    } = p1result;

    let info = Memory {
        memory_map,
        label_set,
        not_found_labels,
    };

    let macro_path = out.join("macros.inc");
    fs::write(&macro_path, ASM_INCLUDE_MACROS).map_err(E::MacroInc)?;

    let nf_syms = out.join("not-found-sym.ld");
    write_notfound_symbols(&nf_syms, &info.not_found_labels).map_err(E::NFSym)?;

    blocks
        .into_par_iter()
        .take(20)
        .try_for_each(|block| write_block(block, &info, &rom, &out))?;

    todo!()
}

fn write_notfound_symbols(p: &Path, syms: &HashMap<u32, Label>) -> io::Result<()> {
    let mut f = BufWriter::new(File::create(p)?);

    writeln!(&mut f, "/* Unknown Symbols */\n")?;
    for (addr, label) in syms {
        writeln!(&mut f, "{} = {:#08X};", label, addr)?;
    }

    Ok(())
}

fn write_block(block: BlockInsn, info: &Memory, rom: &[u8], out: &Path) -> P2Result<()> {
    use Pass2Error as E;

    let name = &block.name;
    let name_str: &str = &name;
    let name_os = OsStr::new(name_str);
    let block_info = info
        .memory_map
        .get_block(name)
        .ok_or_else(|| E::NoBlockInfo(name.clone()))?;
    let block_labels = info.label_set.get_block_map(name);
    let raw_data = {
        let (start, end) = block_info.range.get_rom_offsets();
        &rom[start..end]
    };

    let (text_sections, data_sections) = block.loaded_sections.clone_into_separate();
    let (data_labels, bss_labels) = separate_and_sort_labels(block_info, block_labels);

    let out_base = block_output_dir(out, name_str);
    fs::create_dir_all(&out_base).map_err(|e| E::BlockOut(name.clone(), e))?;

    let raw_bin = make_path(&out_base, &name_os, ".raw.bin");
    fs::write(&raw_bin, raw_data)?;

    let mut asm_file = make_file(&out_base, &name_os, ".text.s")?;
    text::write_block_asm(&mut asm_file, &block, &text_sections, &info)
        .map_err(|e| E::AsmError(name.clone(), e))?;

    let mut data_file = make_file(&out_base, &name_os, ".data.s")?;
    let bin_filename = raw_bin.file_name().expect("valid file").to_string_lossy();
    data::write_block_data(
        &mut data_file,
        &bin_filename,
        &data_labels,
        &data_sections,
        &block,
        &info,
    )
    .map_err(|e| E::DataError(name.clone(), e))?;

    let mut bss_file = make_file(&out_base, &name_os, ".bss.s")?;
    bss::write_block_bss(&mut bss_file, &bss_labels, block_info)?;

    Ok(())
}

fn block_output_dir(base: &Path, block: &str) -> PathBuf {
    base.to_path_buf().join(block)
}

fn make_file(dir: &Path, base: &OsStr, ending: &str) -> io::Result<Wtr> {
    let path = make_path(dir, base, ending);

    File::create(path).map(BufWriter::new)
}

fn make_path(dir: &Path, base: &OsStr, ending: &str) -> PathBuf {
    let mut p = base.to_os_string();
    p.push(ending);
    dir.join(&p)
}

/// Separate a block's non-text labels into a sorted .data Vec and a sorted .bss Vec
fn separate_and_sort_labels<'a>(
    block: &CodeBlock,
    block_labels: &'a HashMap<u32, Label>,
) -> (Vec<&'a Label>, Vec<&'a Label>) {
    fn lower_addr(a: &&Label, b: &&Label) -> Ordering {
        a.addr.cmp(&b.addr)
    }

    let (mut bss, mut data): (Vec<_>, Vec<_>) = block_labels
        .values()
        .filter(|l| l.is_data())
        .filter(|l| block.range.contains(l.addr))
        .partition(|l| {
            block
                .range
                .section(l.addr)
                .map_or(false, |s| s == Section::Bss)
        });

    bss.sort_unstable_by(lower_addr);
    data.sort_unstable_by(lower_addr);

    (data, bss)
}

fn find_label<'a>(mem: &'a Memory, block: &'a BlockInsn, addr: u32) -> Option<&'a Label> {
    use LabelPlace::*;

    let internal_labels = &mem.label_set.get_block_map(&block.name);
    let global_labels = &mem.label_set.globals;
    let notfound_labels = &mem.not_found_labels;
    let overlayed_labels = &mem.label_set.overlays;
    let multi_labels = block.unresolved_labels.as_ref();

    block
        .label_locations
        .get(&addr)
        .and_then(|place| match place {
            Internal => internal_labels.get(&addr),
            Global => global_labels.get(&addr),
            NotFound => notfound_labels.get(&addr),
            External(ref block) => overlayed_labels.get(block).and_then(|lbls| lbls.get(&addr)),
            MultipleExtern => multi_labels.and_then(|lbls| lbls.get(&addr)),
        })
}
