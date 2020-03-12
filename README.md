# n64disasm

A simple disassembler for N64 games based on capstone. It can handle and process overlays. Information about the ROM to disassemble is encoded in the [config files](config/).

It also does some basic data parsing for pointer and null-terminated ASCII strings based on typical patterns from the SGI N64 compilers (IDO, MIPSpro). It probably won't work well for games made with a GCC-based compiler.

One scenario that the disassembler cannot deal with right now is interleaved `.text` and `.data` sections that share one combined `.bss` section for uninitialized data.

## Installation

[Download Rust](http://rustup.rs), and `cargo install --path .` or `cargo run --release`.
