use crate::disasm::{
    instruction::Instruction,
    labels::{Label, LabelSet, LabelKind},
    memmap::{BlockName, MemoryMap},
    pass1::{BlockInsn, Pass1, JumpKind, LinkedVal, LabelPlace},
};
use err_derive::Error;
use std::collections::HashMap;
use std::io::{self, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::fs::{self, File}; 

#[derive(Debug, Error)]
pub enum Pass2Error {
    #[error(display = "Unable to create output directory for {}", _0)]
    BlockOut(String, #[error(source)] io::Error),
    #[error(display = "Unable to write macro.inc file")]
    MacroInc(#[error(source)] io::Error),
    #[error(display = "Unable to disassemble asm for {}", _0)]
    AsmError(BlockName, #[error(source)] AsmWriteError),
}

type P2Result<T> = Result<T, Pass2Error>;

const ASM_INCLUDE_MACROS: &'static str = include_str!("pass2/macros.inc");
const ASM_FILE_PRELUDE: &'static str = include_str!("pass2/prelude.s");

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
    fs::write(&macro_path, ASM_INCLUDE_MACROS)
        .map_err(E::MacroInc)?;

    for block in blocks.into_iter().skip(1).take(1) {
        let out_base = block_output_dir(out, &block.name);
        fs::create_dir_all(&out_base)?;

        let mut asm_file = BufWriter::new(File::create(&out_base.join("asm.s"))?);
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
    #[error(display = "Address {:08x} associated with data label: {:x?}", _0, _1)]
    DataLabel(u32, Label),
    #[error(display = "Unknown instruction combination for finding label: {:x?}", _0)]
    InsnLabel(Instruction),
    #[error(display = "Couldn't find target of branch to {:x}", _0)]
    BranchNotFound(u32),
    #[error(display = "Couldn't find target of jump to {:x}. Expected in {:?}", _0, _1)]
    JumpNotFound(u32, Option<LabelPlace>),
}

fn write_block_asm(
    wtr: &mut BufWriter<File>,
    block: &BlockInsn,
    mem: &Memory,
) -> Result<(), AsmWriteError> {
    use AsmWriteError::*;
    use LabelKind::*;
    use JumpKind::*;
    use LinkedVal::*;

    let name = &block.name;
    let block_info = mem
        .memory_map
        .get_block(name)
        .ok_or_else(|| NoBlockInfo(name.clone()))?;

    let internal_labels = mem.label_set.get_block_map(name);
    let places = &block.label_locations;
    let find_branch = |addr| internal_labels.get(&addr)
        .ok_or_else(|| BranchNotFound(addr));
    let find_jump = |addr| find_jump_label(mem, block, addr)
        .ok_or_else(|| JumpNotFound(addr, places.get(&addr).cloned()));

    
    wtr.write_all(ASM_FILE_PRELUDE.as_bytes())?;
    for insn in &block.instructions {
        // typically between routines
        if insn.new_line {
            writeln!(wtr, "")?;
        }

        if let Some(label) = internal_labels.get(&insn.vaddr) {
            match label.kind {
                Local => writeln!(wtr, "{:2}{}:", "", &label)?,
                Routine | Named(..) => writeln!(wtr, "glabel {}", &label)?,
                Data => writeln!(wtr, "/* {} || Bad Data label for instructions */", &label)?,
            }
        }

        // TODO: what causes 800a26d8 to be entered as a data label, and not a routine?
        //       indirect call?
        // `/* vaddr raw */ instruction {ops | jump target | linked value}`
        write!(wtr, "{:2}/* {:08X} {:08X} */", "", insn.vaddr, insn.raw)?;
        write!(wtr, "{:>8} ", &insn.mnemonic)?;

        match (insn.jump, insn.linked, insn.op_str.as_ref()) {
            (BAL(addr), _, _) | (Branch(addr), _, _) => {
                let target = find_branch(addr)?;
                write!(wtr, "{}", target)?;
            },
            (JAL(addr), _, _) | (Jump(addr), _, _) => {
                let target = find_jump(addr)?;
                write!(wtr, "{}", target)?;
            }
            (_, _, Some(op)) => {
                write!(wtr, "{}", op)?
            },
            _ => Err(InsnLabel(insn.clone()))?,
        }

        writeln!(wtr, "")?;

    }

    Ok(())
}

struct Memory {
    memory_map: MemoryMap,
    label_set: LabelSet,
    not_found_labels: HashMap<u32, Label>,
}

fn find_jump_label<'a>(mem: &'a Memory, block: &'a BlockInsn, addr: u32) -> Option<&'a Label> {
    use LabelPlace::*;

    let internal_labels = &mem.label_set.get_block_map(&block.name);
    let global_labels = &mem.label_set.globals;
    let notfound_labels = &mem.not_found_labels;
    let overlayed_labels = &mem.label_set.overlays;
    let multi_labels = block.unresolved_labels.as_ref();

    block.label_locations.get(&addr).and_then(|place| {
        match place {
            Internal => internal_labels.get(&addr),
            Global => global_labels.get(&addr),
            NotFound => notfound_labels.get(&addr),
            External(ref block) => overlayed_labels.get(block)
                .and_then(|lbls| lbls.get(&addr)),
            MultipleExtern => multi_labels
                .and_then(|lbls| lbls.get(&addr)),
        }
    })
}
