mod boolext;
mod config;
mod disasm;

use log::error;
use simplelog::{ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::error::Error;
use std::path::PathBuf;
use structopt::StructOpt;

/// A program to disassemble big endian N64 roms based on a based YAML config.
/// It supports dissassembly of overlayed code.
#[derive(Debug, StructOpt)]
pub struct Opts {
    /// Path to the ROM to be disassembled
    #[structopt(parse(from_os_str))]
    rom: PathBuf,
    /// Path to the ROM configuration YAML file
    #[structopt(parse(from_os_str))]
    config: PathBuf,
    /// Output directory to write ASM files, or config name if not supplied
    #[structopt(parse(from_os_str))]
    outdir: Option<PathBuf>,
    /// Print additional information (up to 3)
    #[structopt(short, long, parse(from_occurrences))]
    verbose: u8,
}

fn main() {
    let opts = Opts::from_args();

    if let Err(e) = run(opts) {
        error!("error:     {}", e);
        let mut cause = e.source();
        while let Some(e) = cause {
            error!("caused by: {}", e);
            cause = e.source();
        }
        ::std::process::exit(1)
    }
}

fn run(opts: Opts) -> Result<(), Box<dyn Error>> {
    let config = ConfigBuilder::new()
        .set_time_level(LevelFilter::Off)
        .build();
    let log_level = get_log_level(opts.verbose);
    TermLogger::init(log_level, config, TerminalMode::Mixed)?;

    let config = config::parse_config(&opts.config)?;

    disasm::disasm_all(config, opts)?;

    Ok(())
}

fn get_log_level(v: u8) -> LevelFilter {
    match v {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}
