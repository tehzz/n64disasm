mod csutil;
mod instruction;
pub mod labels;
pub mod memmap;
mod mipsvals;
mod pass1;
mod pass2;

use crate::config::Config;
use crate::Opts;
use err_derive::Error;
use log::{info, debug, log_enabled, Level::Debug};
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

    if log_enabled!(Debug) {
        let labels = &pass1.labels;

        debug!("Global Labels ({}):", labels.globals.len());
        for (_addr, label) in &labels.globals {
            debug!("{:4}{} << {:x?}", "", &label, &label);
        }
        debug!("Overlayed Labels:");
        for (block, set) in &labels.overlays {
            debug!("{:4}{} ({} labels):", "", &block, set.len());
            for (_addr, label) in set {
                debug!("{:8}{} << {:x?}", "", &label, &label);
            }
        }
    }

    let outdir = outdir
        .or_else(|| default_output_dir(&config_path))
        .ok_or(E::NoDefaultDir)?;

    info!("Output Directory: {:?}", &outdir);
    if outdir.is_file() {
        return Err(E::NotOutDir(outdir));
    }

    fs::create_dir_all(&outdir)?;

    pass2(pass1, &outdir)?;

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
