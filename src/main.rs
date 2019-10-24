mod config;
mod disasm;

use std::error::Error;
use std::path::PathBuf;
use structopt::StructOpt;

/// A program to disassemble big endian N64 roms based on a based YAML config.
/// It supports dissassembly of overlayed code.
#[derive(Debug, StructOpt)]
struct Opts {
    /// Path to the ROM to be disassembled
    #[structopt(parse(from_os_str))]
    rom: PathBuf,
    /// Path to the ROM configuration YAML file
    #[structopt(parse(from_os_str))]
    config: PathBuf,
    /// Output directory to write ASM files
    #[structopt(parse(from_os_str))]
    outdir: Option<PathBuf>,
}

fn main() {
    let opts = Opts::from_args();

    if let Err(e) = run(opts) {
        eprintln!("error:     {}", e);
        let mut cause = e.source();
        while let Some(e) = cause {
            eprintln!("caused by: {}", e);
            cause = e.source();
        }
        ::std::process::exit(1)
    }
}

fn run(opts: Opts) -> Result<(), Box<dyn Error>> {
    let config = config::parse_config(&opts.config)?;
    disasm::pass1(config, &opts.rom)?;

    Ok(())
}
