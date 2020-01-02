mod csutil;
mod instruction;
pub mod labels;
pub mod memmap;
mod mipsvals;
mod pass1;

use crate::config::Config;
use crate::Opts;
use err_derive::Error;
use log::info;
use pass1::{pass1, Pass1Error};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Error)]
pub enum DisasmError {
    #[error(display = "Couldn't generate a default output directory")]
    NoDefaultDir,
    #[error(display = "Provided output directory <{:?}> is not a directory", _0)]
    NotOutDir(PathBuf),
    #[error(display = "Issue with pass 1 of disassembly")]
    Pass1(#[error(source)] Pass1Error),
    #[error(display = "Issue creating output directory")]
    Io(#[error(source)] ::std::io::Error),
}

pub fn disasm_all(config: Config, opts: Opts) -> Result<(), DisasmError> {
    use DisasmError as E;

    let Opts {
        rom,
        outdir,
        config: config_path,
    } = opts;

    let pass1 = pass1(config, &rom)?;
    let outdir = outdir
        .or_else(|| generate_output_dir(&config_path))
        .ok_or(E::NoDefaultDir)?;

    info!("Output Directory: {:?}", &outdir);
    if outdir.is_file() {
        return Err(E::NotOutDir(outdir));
    }

    fs::create_dir_all(&outdir)?;

    Ok(())
}

/// If the user doesn't provide a output directory for the set of generated ASM files,
/// try to use the name of the config file to make a generic output location
fn generate_output_dir(config: &Path) -> Option<PathBuf> {
    use std::ffi::OsStr;

    let name = config.file_stem();
    let mut base = OsStr::new("output-").to_os_string();

    name.map(move |n| {
        base.push(n);
        base.into()
    })
}
