mod bss;
mod data;
mod text;

use crate::disasm::{
    labels::{Label, LabelSet},
    memmap::{BlockName, MemoryMap},
    pass1::{BlockInsn, Pass1},
};
use err_derive::Error;
use rayon::prelude::*;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

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
}

type P2Result<T> = Result<T, Pass2Error>;
type Wtr = BufWriter<File>;

const ASM_INCLUDE_MACROS: &'static str = include_str!("pass2/inc/macros.inc");

struct Memory {
    memory_map: MemoryMap,
    label_set: LabelSet,
    not_found_labels: HashMap<u32, Label>,
}

pub fn pass2(p1result: Pass1, out: &Path) -> P2Result<()> {
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
        .try_for_each(|block| write_block(block, &info, &out))?;

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

fn write_block(block: BlockInsn, info: &Memory, out: &Path) -> P2Result<()> {
    use Pass2Error as E;

    let name = &block.name;
    let name_str: &str = &name;
    let name_os = OsStr::new(name_str);
    let block_info = info
        .memory_map
        .get_block(name)
        .ok_or_else(|| E::NoBlockInfo(name.clone()))?;
    let (text_sections, data_sections) = block.loaded_sections.clone_into_separate();

    let out_base = block_output_dir(out, name_str);
    fs::create_dir_all(&out_base).map_err(|e| E::BlockOut(name.clone(), e))?;

    let mut asm_file = make_file(&out_base, &name_os, ".text.s")?;
    text::write_block_asm(&mut asm_file, &block, &text_sections, &info)
        .map_err(|e| E::AsmError(name.clone(), e))?;

    let mut bss_file = make_file(&out_base, &name_os, ".bss.s")?;
    bss::write_block_bss(
        &mut bss_file,
        info.label_set.get_block_map(name),
        &block_info,
    )?;

    Ok(())
}

fn block_output_dir(base: &Path, block: &str) -> PathBuf {
    base.to_path_buf().join(block)
}

fn make_file(dir: &Path, base: &OsStr, ending: &str) -> io::Result<Wtr> {
    let mut f = base.to_os_string();
    f.push(ending);

    File::create(dir.join(&f)).map(BufWriter::new)
}
