mod bss;
mod data;
mod symbols;
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

use bss::BssWriteErr;
use data::DataWriteErr;
use text::AsmWriteErr;

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
    AsmError(BlockName, #[error(source)] AsmWriteErr),
    #[error(display = "Unable to output data for {}", _0)]
    DataError(BlockName, #[error(source)] DataWriteErr),
    #[error(display = "Unable to output bss for {}", _0)]
    BssError(BlockName, #[error(source)] BssWriteErr),
}

type P2Result<T> = Result<T, Pass2Error>;
type Wtr = BufWriter<File>;

const ASM_INCLUDE_MACROS: &str = include_str!("pass2/inc/macros.inc");

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
    write_symbols_ldscript(
        &nf_syms,
        &info.not_found_labels,
        "Symbols that couldn't be found",
    )
    .map_err(E::NFSym)?;

    blocks
        .into_par_iter()
        .try_for_each(|block| write_block(block, &info, &rom, &out))
}

fn write_symbols_ldscript(p: &Path, syms: &HashMap<u32, Label>, com: &str) -> io::Result<()> {
    let mut f = BufWriter::new(File::create(p)?);
    let mut sorted_syms = syms.values().collect::<Vec<_>>();
    sorted_syms.sort_unstable_by(lower_addr);

    writeln!(&mut f, "/* {} */\n", com)?;
    for label in sorted_syms {
        writeln!(&mut f, "{} = {:#08X};", label, label.addr)?;
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
    let (raw_data, ram_to_rom) = {
        let (start, end) = block_info.range.get_rom_offsets();
        let ram_start = block_info.range.get_ram_start();
        (&rom[start..end], ram_start - start as u32)
    };

    let (text_sections, data_sections) = block.loaded_sections.clone_into_separate();
    let (data_labels, bss_labels) = separate_and_sort_labels(&block, block_info, block_labels);

    let out_base = block_output_dir(out, name_str);
    fs::create_dir_all(&out_base).map_err(|e| E::BlockOut(name.clone(), e))?;
    let make_file = |s| make_file(&out_base, &name_os, s);

    let raw_bin = make_path(&out_base, &name_os, ".raw.bin");
    fs::write(&raw_bin, raw_data)?;

    let mut asm_file = make_file(".text.s")?;
    text::write_block_asm(&mut asm_file, &block, &text_sections, &info, ram_to_rom)
        .map_err(|e| E::AsmError(name.clone(), e))?;

    let mut data_file = make_file(".data.s")?;
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

    if block_info.range.get_bss().is_some() {
        let mut bss_file = make_file(".bss.s")?;
        bss::write_block_bss(&mut bss_file, &bss_labels, block_info)
            .map_err(|e| E::BssError(name.clone(), e))?;
        //todo generalize error map fn
    }

    symbols::write_symbols(&block, &block_info.range, info, make_file)?;

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
    insn: &BlockInsn,
    block: &CodeBlock,
    block_labels: &'a HashMap<u32, Label>,
) -> (Vec<&'a Label>, Vec<&'a Label>) {
    let (mut bss, mut data): (Vec<_>, Vec<_>) = block_labels
        .values()
        .filter_map(|l| {
            get_data_and_bss(l, insn, block)
                .map(is_bss_not_data)
                .map(|is_bss| (l, is_bss))
        })
        .fold((Vec::new(), Vec::new()), |mut acc, (l, is_bss)| {
            if is_bss {
                acc.0.push(l)
            } else {
                acc.1.push(l)
            }

            acc
        });

    bss.sort_unstable_by(lower_addr);
    data.sort_unstable_by(lower_addr);

    (data, bss)
}

fn get_data_and_bss(label: &Label, insns: &BlockInsn, block: &CodeBlock) -> Option<Section> {
    let data_or_bss = |sec| match sec {
        Section::Bss => Some(sec),
        Section::Data => Some(sec),
        Section::Text | Section::TextData => None,
    };

    // loaded sections has info on .text and .data, while block.range has info on .bss
    insns
        .loaded_sections
        .find_address(label.addr)
        .map(|s| s.kind)
        .and_then(data_or_bss)
        .or_else(|| block.range.section(label.addr).and_then(data_or_bss))
}

fn is_bss_not_data(sec: Section) -> bool {
    match sec {
        Section::Bss => true,
        Section::Data => false,
        _ => unreachable!(),
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn lower_addr(a: &&Label, b: &&Label) -> Ordering {
    a.addr.cmp(&b.addr)
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
