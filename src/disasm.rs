mod csutil;
mod hwreg;
mod instruction;
pub mod labels;
pub mod memmap;
mod mipsvals;
mod pass1;
mod pass2;

use crate::config::Config;
use crate::Opts;
use err_derive::Error;
use log::{debug, info};
use pass1::{pass1, Pass1Error};
use pass2::{pass2, Pass2Error};
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
    #[error(display = "Issue with pass 2 of disassembly")]
    Pass2(#[error(source)] Pass2Error),
    #[error(display = "Issue reading ROM into memory")]
    Rom(#[error(no_from, source)] ::std::io::Error),
    #[error(display = "Issue creating output directory")]
    OutDir(#[error(no_from, source)] ::std::io::Error),
}

pub fn disasm_all(config: Config, opts: Opts) -> Result<(), DisasmError> {
    use DisasmError as E;

    let Opts {
        rom,
        outdir,
        config: config_path,
        ..
    } = opts;

    let rom = fs::read(&rom).map_err(E::Rom)?;
    let pass1 = pass1(config, &rom)?;

    debug!("{}", &pass1.labels);

    let outdir = outdir
        .or_else(|| default_output_dir(&config_path))
        .ok_or(E::NoDefaultDir)?;

    info!("Output Directory: {:?}", &outdir);
    if outdir.is_file() {
        return Err(E::NotOutDir(outdir));
    }

    fs::create_dir_all(&outdir).map_err(E::OutDir)?;

    pass2(pass1, &rom, &outdir)?;

    Ok(())
}

/// If the user doesn't provide a output directory for the set of generated ASM files,
/// try to use the name of the config file to make a generic output location
fn default_output_dir(config: &Path) -> Option<PathBuf> {
    use std::ffi::OsString;

    let name = config.file_stem();
    let mut base = OsString::new();

    name.map(move |n| {
        base.push(n);
        base.push(".split");
        base.into()
    })
}
