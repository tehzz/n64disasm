use crate::disasm::{
    instruction::Instruction,
    labels::{Label, LabelKind, LabelLoc, LabelSet},
    memmap::{BlockName, MemoryMap},
    pass1::{BlockInsn, JumpKind, LabelPlace, LinkedVal, Link, Pass1},
};
use err_derive::Error;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Error)]
pub enum Pass2Error {
    #[error(display = "Unable to create output directory for {}", _0)]
    BlockOut(BlockName, #[error(source)] io::Error),
    #[error(display = "Unable to write macro.inc file")]
    MacroInc(#[error(source)] io::Error),
    #[error(display = "Unable to disassemble asm for {}", _0)]
    AsmError(BlockName, #[error(source)] AsmWriteError),
}

type P2Result<T> = Result<T, Pass2Error>;

const ASM_INCLUDE_MACROS: &'static str = include_str!("pass2/macros.inc");
const ASM_FILE_PRELUDE: &'static str = include_str!("pass2/prelude.s");

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

    for block in blocks.into_iter().skip(1).take(3) {
        let name: &str = &block.name;
        let out_base = block_output_dir(out, name);
        fs::create_dir_all(&out_base)
            .map_err(|e| E::BlockOut(block.name.clone(), e))?;

        let block_os = OsStr::new(name);
        let asm_filename = {
            let mut f = block_os.to_os_string();
            f.push(".text.s");
            f
        };
        let mut asm_file = BufWriter::new(File::create(&out_base.join(&asm_filename))?);
        write_block_asm(&mut asm_file, &block, &info)
            .map_err(|e| E::AsmError(block.name.clone(), e))?;
    }

    todo!()
}

fn block_output_dir(base: &Path, block: &str) -> PathBuf {
    base.to_path_buf().join(block)
}

#[derive(Debug, Error)]
pub enum AsmWriteError {
    #[error(display = "Block name <{}> missing information", _0)]
    NoBlockInfo(BlockName),
    #[error(display = "Issue writing asm to output")]
    Io(#[error(source)] io::Error),
    #[error(
        display = "Unknown instruction combination for finding label: {:x?}",
        _0
    )]
    InsnLabel(Instruction),
    #[error(display = "Couldn't find target of branch to {:x}", _0)]
    BranchNotFound(u32),
    #[error(
        display = "Couldn't find target of jump to {:x}. Expected in {:?}",
        _0,
        _1
    )]
    JumpNotFound(u32, Option<LabelPlace>),
    #[error(
        display = "Address {:08x} referred to an Unspecified label: {:?}",
        _0,
        _1
    )]
    UnspecifiedLabel(u32, Label),
    #[error(display = "Couldn't print instruction at {:08x} due to missing op string", _0)]
    MissingOpString(u32),
    #[error(display = "Instruction at {:08x} did not have expect load/store op string", _0)]
    BadLS(u32),
}

fn write_block_asm(
    wtr: &mut BufWriter<File>,
    block: &BlockInsn,
    mem: &Memory,
) -> Result<(), AsmWriteError> {
    use AsmWriteError::*;
    use JumpKind::*;
    use LabelKind::*;
    use LinkedVal::*;

    let name = &block.name;
    let block_info = mem
        .memory_map
        .get_block(name)
        .ok_or_else(|| NoBlockInfo(name.clone()))?;

    let internal_labels = mem.label_set.get_block_map(name);
    let find_branch = |addr| {
        internal_labels
            .get(&addr)
            .ok_or_else(|| BranchNotFound(addr))
    };

    wtr.write_all(ASM_FILE_PRELUDE.as_bytes())?;
    for insn in &block.instructions {
        // typically between routines
        if insn.new_line {
            writeln!(wtr, "")?;
        }

        // label address if necessary
        if let Some(label) = internal_labels.get(&insn.vaddr) {
            match label.kind {
                Local => writeln!(wtr, "{:2}{}:", "", &label)?,
                Routine | Named(..) => writeln!(wtr, "glabel {}", &label)?,
                Data => writeln!(wtr, "glabel {}   # Routine parsed as data", &label)?,
            }
        }

        // TODO: what causes 800a26d8 to be entered as a data label, and not a routine?
        // `/* vaddr raw */ instruction {ops | jump target | linked value}`
        write!(wtr, "{:2}/* {:08X} {:08X} */", "", insn.vaddr, insn.raw)?;
        // pad to 10 chars for `trunc.x.y` instruction
        write!(wtr, "{:>10} ", &insn.mnemonic)?;

        match (insn.jump, insn.linked, insn.op_str.as_ref()) {
            (BAL(addr), _, _) | (Branch(addr), _, _) => {
                let target = find_branch(addr)?;
                write!(wtr, "{}", target)?;
            }
            (JAL(addr), _, _) | (Jump(addr), _, _) => {
                write_jump_target(wtr, block, mem, addr)?;
            }
            (_, Empty, Some(op)) => write!(wtr, "{}", op)?,
            (None, _, _) => write_linked_insn(wtr, block, mem, insn)?,
            _ => Err(InsnLabel(insn.clone()))?,
        }

        writeln!(wtr, "")?;
    }

    Ok(())
}

fn write_linked_insn(
    wtr: &mut BufWriter<File>,
    block: &BlockInsn,
    mem: &Memory,
    insn: &Instruction,
) -> Result<(), AsmWriteError> {
    use LinkedVal::*;
    type Wtr<'a> = &'a mut BufWriter<File>;

    let op = insn.truncate_op_imm().ok_or_else(|| AsmWriteError::MissingOpString(insn.vaddr))?;
    let full_op = insn.op_str.as_ref().ok_or_else(|| AsmWriteError::MissingOpString(insn.vaddr))?;
    
    let find_label = |addr| find_label(mem, block, addr);
    let write_label = |w: Wtr, f, l: Link| {
        if let Some(label) = find_label(l.value) {
            write!(w, "{}, %{}({})", op, f, label)
        } else {
            write!(w, "{}, ${}({:#08X}) # Warning: couldn't find matching label", op, f, l.value)
        }
    };
    let write_label_offset = |w: Wtr, l: Link, o| {
        if let Some(label) = find_label(l.value) {
            write!(w, "{} # {} + {}", full_op, label, o)
        } else {
            write!(w, "{} # {:#08X} + {}", full_op, l.value, o)
        }
    };

    match insn.linked {
        Pointer(l) => write_label(wtr, "lo", l)?,
        PtrLui(l) => write_label(wtr, "hi", l)?,
        PtrEmbed(l) => write_embed_ptr(wtr, l, insn, &find_label)?,
        PtrOff(l, o) => write_label_offset(wtr, l, o)?,
        Immediate(l) => write!(wtr, "{}, ({v:#X} & 0xFFFF) # {v}", op, v = l.value)?,
        ImmLui(l) => write!(wtr, "{}, ({v:#X} >> 16) # {v}", op, v = l.value)?,
        Float(l) => write!(wtr, "{}, {:#08X} # {}", op, l.value, f32::from_bits(l.value))?,
        FloatLoad(l) => write!(wtr, "{} # moved float {} to cop1", op, f32::from_bits(l.value))?,
        Empty => unreachable!(),
    };

    Ok(())
}

fn write_embed_ptr<'f>(w: &mut BufWriter<File>, l: Link, insn: &Instruction, find_label: impl Fn(u32) -> Option<&'f Label>) -> Result<(), AsmWriteError> {
    let (dst, base) = insn.ls_components().ok_or_else(|| AsmWriteError::BadLS(insn.vaddr))?;
    let val = l.value;

    if let Some(label) = find_label(val) {
        write!(w, "{}, %lo({}){}", dst, label, base)
    } else {
        write!(w, "{}, %lo({:#08X}){}", dst, val, base)
    }.map_err(Into::into)
}

fn write_jump_target(
    wtr: &mut BufWriter<File>,
    block: &BlockInsn,
    mem: &Memory,
    addr: u32,
) -> Result<(), AsmWriteError> {
    use AsmWriteError::*;
    use LabelLoc::*;

    let find_ovl_labels = |ovl| mem.label_set.overlays[ovl].get(&addr);

    let target = find_label(mem, block, addr)
        .ok_or_else(|| JumpNotFound(addr, block.label_locations.get(&addr).cloned()))?;

    let mut comma = false;
    match target.location {
        Global | Overlayed(..) => write!(wtr, "{}", target).map_err(Into::into),
        Multiple(ref blocks) => {
            write!(wtr, "{} # possible labels: ", target)?;
            blocks
                .iter()
                .filter_map(find_ovl_labels)
                .try_for_each(|l| {
                    write!( wtr, "{}{}", if comma { ", " } else { comma = true; "" }, l )
                })
                .map_err(Into::into)
        }
        UnresolvedMultiple(ref blocks) => {
            write!(wtr, "{} # located somewhere in: ", target)?;
            blocks
                .iter()
                .try_for_each(|ovl| {
                    write!( wtr, "{}{}", if comma { ", " } else { comma = true; "" }, ovl )
                })
                .map_err(Into::into)
        }
        NotFound => write!(wtr, "{} # couldn't be resolved", target).map_err(Into::into),
        Unspecified => Err(UnspecifiedLabel(addr, target.clone())),
    }
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
