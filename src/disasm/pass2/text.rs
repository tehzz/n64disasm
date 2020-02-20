use crate::boolext::BoolOptionExt;
use crate::disasm::{
    instruction::Instruction,
    labels::{Label, LabelKind, LabelLoc},
    pass1::{
        BlockInsn, BlockLoadedSections, FileBreak, JumpKind, LabelPlace, Link, LinkedVal,
        LoadSectionInfo,
    },
    pass2::{Memory, Wtr},
};
use err_derive::Error;
use std::io::{self, Write};

#[derive(Debug, Error)]
pub enum AsmWriteError {
    #[error(display = "Issue writing asm to output")]
    Io(#[error(source)] io::Error),
    #[error(display = "Unknown instruction type for printing: {:x?}", _0)]
    InsnLabel(Instruction),
    #[error(display = "Couldn't find target of branch to {:x}", _0)]
    BranchNotFound(u32),
    #[error(display = "Couldn't find jump target {:x}. Expected in {:?}", _0, _1)]
    JumpNotFound(u32, Option<LabelPlace>),
    #[error(display = "Address {:08x} referred to Unspecified label: {:?}", _0, _1)]
    UnspecifiedLabel(u32, Label),
    #[error(display = "Instruction did not have expected op string\n{:#x?}", _0)]
    MissingOpString(Instruction),
    #[error(display = "Expected load/store instruction, got\n{:#x?}", _0)]
    BadLS(Instruction),
}

const ASM_FILE_PRELUDE: &'static str = include_str!("inc/prelude.text.s");

pub(super) fn write_block_asm(
    wtr: &mut Wtr,
    block: &BlockInsn,
    text_sections: &BlockLoadedSections,
    mem: &Memory,
) -> Result<(), AsmWriteError> {
    use AsmWriteError::*;
    use JumpKind::*;
    use LabelKind::*;
    use LinkedVal::*;

    let name = &block.name;

    let internal_labels = mem.label_set.get_block_map(name);
    let find_branch = |addr| {
        internal_labels
            .get(&addr)
            .ok_or_else(|| BranchNotFound(addr))
    };

    wtr.write_all(ASM_FILE_PRELUDE.as_bytes())?;
    writeln!(wtr, "# Text Sections")?;
    for sec in text_sections.as_slice() {
        writeln!(wtr, "#  {:#08X} -> {:#08X}", sec.range.start, sec.range.end)?;
    }
    writeln!(wtr, "")?;

    let mut cur_section: Option<&LoadSectionInfo> = None;
    let mut hidden;
    for insn in &block.instructions {
        // check if new .text section
        cur_section = cur_section
            .and_then(|sec| sec.range.contains(&insn.vaddr).b_then(sec))
            .or_else(|| text_sections.find_address(insn.vaddr));

        // comment out instructions that aren't in a .text section
        hidden = if cur_section.is_none() { "#" } else { "" };
        // typically between routines
        if insn.new_line {
            writeln!(wtr, "{}", hidden)?;
        }

        // mark if this instruction could be the start of a new file
        match insn.file_break {
            FileBreak::Likely => writeln!(wtr, "\n# Likely start of new file")?,
            FileBreak::Possible => writeln!(wtr, "# Maybe start of new file")?,
            FileBreak::Nope => (),
        }

        // label address if necessary
        if let Some(label) = internal_labels.get(&insn.vaddr) {
            write!(wtr, "{}", hidden)?;
            match label.kind {
                Local => writeln!(wtr, "{:2}{}:", "", &label)?,
                Routine | Named(..) => writeln!(wtr, "glabel {}", &label)?,
                Data => writeln!(wtr, "glabel {}   # Routine parsed as data", &label)?,
            }
        }

        // `/* vaddr raw */ instruction {ops | jump target | linked value}`
        write!(wtr, "{}", hidden)?;
        write!(wtr, "{:2}/* {:08X} {:08X} */", "", insn.vaddr, insn.raw)?;
        // pad to 10 chars for `trunc.x.y` instruction
        write!(wtr, "{:>10} ", &insn.mnemonic)?;

        match (insn.jump, insn.linked, insn.op_str.as_ref()) {
            (BAL(addr), _, _) | (Branch(addr), _, _) => {
                let target = find_branch(addr)?;
                write!(wtr, "{}", target)?;
            }
            (BranchCmp(addr), _, _) => {
                let target = find_branch(addr)?;
                let op = insn
                    .truncate_op_imm()
                    .ok_or_else(|| MissingOpString(insn.clone()))?;
                write!(wtr, "{}, {}", op, target)?;
            }
            (JAL(addr), _, _) | (Jump(addr), _, _) => {
                write_jump_target(wtr, block, mem, addr)?;
            }
            (_, Empty, Some(op)) => write!(wtr, "{}", op)?,
            (NoJump, _, _) => write_linked_insn(wtr, block, mem, insn)?,
            _ => Err(InsnLabel(insn.clone()))?,
        }

        writeln!(wtr, "")?;
    }

    Ok(())
}

fn write_linked_insn(
    wtr: &mut Wtr,
    block: &BlockInsn,
    mem: &Memory,
    insn: &Instruction,
) -> Result<(), AsmWriteError> {
    use AsmWriteError::*;
    use LinkedVal::*;

    let op = insn
        .truncate_op_imm()
        .ok_or_else(|| MissingOpString(insn.clone()))?;
    let full_op = insn
        .op_str
        .as_ref()
        .ok_or_else(|| MissingOpString(insn.clone()))?;

    let find_label = |addr| find_label(mem, block, addr);
    let write_label = |w: &mut Wtr, f, l: Link| {
        if let Some(label) = find_label(l.value) {
            write!(w, "{}, %{}({})", op, f, label)
        } else {
            write!(
                w,
                "{}, ${}({:#08X}) # Warning: couldn't find matching label",
                op, f, l.value
            )
        }
    };
    let write_label_offset = |w: &mut Wtr, l: Link, o| {
        if let Some(label) = find_label(l.value) {
            write!(w, "{} # {} + {}", full_op, label, o)
        } else {
            write!(w, "{} # {:#08X} + {}", full_op, l.value, o)
        }
    };

    match insn.linked {
        Pointer(l) => write_label(wtr, "lo", l)?,
        PtrLui(l) => write_label(wtr, "hi", l)?,
        PtrEmbed(l) | FloatPtr(l) | DoublePtr(l) => write_embed_ptr(wtr, l, insn, &find_label)?,
        PtrOff(l, o) => write_label_offset(wtr, l, o)?,
        Immediate(l) => write!(wtr, "{}, ({v:#X} & 0xFFFF) # {v}", op, v = l.value)?,
        ImmLui(l) => write!(wtr, "{}, ({v:#X} >> 16) # {v}", op, v = l.value)?,
        Float(l) => write!(
            wtr,
            "{}, {:#08X} # {}",
            op,
            l.value,
            f32::from_bits(l.value)
        )?,
        FloatLoad(l) => write!(
            wtr,
            "{} # moved float {} to cop1",
            full_op,
            f32::from_bits(l.value)
        )?,
        Empty => unreachable!(),
    };

    Ok(())
}

fn write_embed_ptr<'f>(
    w: &mut Wtr,
    l: Link,
    insn: &Instruction,
    find_label: impl Fn(u32) -> Option<&'f Label>,
) -> Result<(), AsmWriteError> {
    let (dst, base) = insn
        .ls_components()
        .ok_or_else(|| AsmWriteError::BadLS(insn.clone()))?;
    let val = l.value;

    if let Some(label) = find_label(val) {
        write!(w, "{}, %lo({}){}", dst, label, base)
    } else {
        write!(w, "{}, %lo({:#08X}){}", dst, val, base)
    }
    .map_err(Into::into)
}

fn write_jump_target(
    wtr: &mut Wtr,
    block: &BlockInsn,
    mem: &Memory,
    addr: u32,
) -> Result<(), AsmWriteError> {
    use AsmWriteError::*;
    use LabelLoc::*;

    let find_ovl_labels = |ovl| mem.label_set.overlays[ovl].get(&addr);

    let target = find_label(mem, block, addr)
        .ok_or_else(|| JumpNotFound(addr, block.label_locations.get(&addr).cloned()))?;

    let mut comma = "";
    match target.location {
        Global | Overlayed(..) => write!(wtr, "{}", target).map_err(Into::into),
        Multiple(ref blocks) => {
            write!(wtr, "{} # possible labels: ", target)?;
            blocks
                .iter()
                .filter_map(find_ovl_labels)
                .try_for_each(|label| {
                    write!(wtr, "{}{}", comma, label)
                        .map(|_| comma = ", ")
                        .map_err(Into::into)
                })
        }
        UnresolvedMultiple(ref blocks) => {
            write!(wtr, "{} # located somewhere in: ", target)?;
            blocks.iter().try_for_each(|ovl| {
                write!(wtr, "{}{}", comma, ovl)
                    .map(|_| comma = ", ")
                    .map_err(Into::into)
            })
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
