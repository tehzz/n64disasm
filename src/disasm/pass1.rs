use crate::config::Config;
use crate::disasm::CodeBlock;
use arrayvec::ArrayString;
use capstone::{arch::mips::MipsOperand, prelude::*, Insn};
use err_derive::Error;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Error)]
pub enum Pass1Error {
    #[error(display = "MIPS opcode mnemonic longer than 16 bytes: {}", _0)]
    LongMnem(String),
    #[error(
        display = "Expected a MIPS instruction of four bytes, received <{:x?}>",
        _0
    )]
    IllegalInsn(Vec<u8>, #[error(source)] ::std::array::TryFromSliceError),
    #[error(display = "Problem reading ROM in pass 1 disassembly")]
    Io(#[error(source)] ::std::io::Error),
    #[error(display = "Problem with capstone disassembly")]
    Capstone(#[error(source)] capstone::Error),
}

pub fn pass1(config: Config, rom: &Path) -> Result<(), Pass1Error> {
    let Config {
        blocks: config_blocks,
        ..
    } = config;
    let cs = Capstone::new()
        .mips()
        .detail(true)
        .mode(arch::mips::ArchMode::Mips64)
        .endian(capstone::Endian::Big)
        .build()?;

    let mut rom = File::open(rom)?;
    let read_rom = |block: CodeBlock| -> io::Result<(CodeBlock, Vec<u8>)> {
        let CodeBlock {
            rom_start: start,
            rom_end: end,
            ..
        } = block;
        let size = (end - start) as usize;
        let mut buf = vec![0u8; size];

        rom.seek(SeekFrom::Start(start as u64))?;
        rom.read_exact(&mut buf)?;

        Ok((block, buf))
    };

    for res in config_blocks.into_iter().map(read_rom).take(1) {
        let (block, buf) = res?;
        let insns = cs.disasm_all(&buf, block.vaddr as u64)?;

        println!(
            "Found {} instructions in block '{}'",
            insns.len(),
            &block.name
        );

        insns
            .iter()
            .take(100)
            .inspect(|i| println!("{}", i))
            .map(|i| {
                let detail = cs.insn_detail(&i)?;
                Instruction::from_components(&i, &detail)
            })
            .scan(NLState::Clear, |s, r| {
                r.map(|i| indicate_newlines(s, i)).transpose()
            })
            .for_each(|converted| println!("{:#?}\n", &converted));
    }

    Ok(())
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum NLState {
    Clear,
    Delay,
    NewLine,
}

// shouldn't have a jump in the delay slot of a jump, as that is undefined in MIPS.
// So, there no worry about overlapping jump/branches
fn indicate_newlines(state: &mut NLState, mut insn: Instruction) -> Option<Instruction> {
    use capstone::arch::mips::MipsReg::*;
    use NLState::*;

    insn.new_line = *state == NewLine;

    *state = match state {
        Delay => NewLine,
        Clear | NewLine => match insn.target {
            JumpKind::Jump(_) => Delay,
            JumpKind::JumpRegister(reg) if reg.0 as u32 == MIPS_REG_RA => Delay,
            _ => Clear,
        },
    };

    Some(insn)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum JumpKind {
    None,
    Branch(u32),
    BAL(u32),
    Jump(u32),
    JAL(u32),
    JumpRegister(RegId),
}

impl From<(&Insn<'_>, &InsnDetail<'_>)> for JumpKind {
    fn from((insn, details): (&Insn, &InsnDetail)) -> Self {
        use capstone::arch::mips::MipsInsn::*;
        use capstone::arch::mips::MipsInsnGroup::*;

        if !details.groups().any(|g| g.0 as u32 == MIPS_GRP_JUMP) {
            return Self::None;
        }

        let imm = details
            .arch_detail()
            .mips()
            .expect("All decompiled instructions should be MIPS")
            .operands()
            .find_map(|op| match op {
                MipsOperand::Imm(val) => Some(val as u32),
                _ => None,
            });

        let reg = details
            .arch_detail()
            .mips()
            .expect("All decompiled instructions should be MIPS")
            .operands()
            .find_map(|op| match op {
                MipsOperand::Reg(r) => Some(r),
                _ => None,
            });

        let jump = MIPS_INS_J as u32;
        let jal = MIPS_INS_JAL as u32;
        let bal = MIPS_INS_BAL as u32;

        if let Some(imm) = imm {
            match insn.id().0 {
                op if op == jump => JumpKind::Jump(imm),
                op if op == jal => JumpKind::JAL(imm),
                op if op == bal => JumpKind::BAL(imm),
                _ => JumpKind::Branch(imm),
            }
        } else if let Some(jrra_target) = reg {
            // catch `jr XX` and `jalr XX`
            JumpKind::JumpRegister(jrra_target)
        } else {
            unreachable!("Not all branch/jump types covered?");
        }
    }
}

#[derive(Debug)]
struct Instruction {
    id: capstone::InsnId,
    vaddr: u32,
    raw: u32,
    // same size as an `(A)Rc<str>` on 64bit, but no indirection/thread issues
    mnemonic: ArrayString<[u8; 16]>,
    op_str: Option<String>,
    operands: Vec<MipsOperand>,
    new_line: bool,
    target: JumpKind,
    //linked_insn: usize,
}

impl Instruction {
    fn from_components(insn: &Insn, detail: &InsnDetail) -> Result<Self, Pass1Error> {
        use Pass1Error::{IllegalInsn, LongMnem};

        let mnemonic = insn.mnemonic().expect("MIPS Opcode Mnemonic");

        Ok(Self {
            id: insn.id(),
            vaddr: insn.address() as u32,
            raw: insn
                .bytes()
                .try_into()
                .map(u32::from_be_bytes)
                .map_err(|e| IllegalInsn(insn.bytes().to_vec(), e))?,
            mnemonic: ArrayString::from(mnemonic).map_err(|_| LongMnem(mnemonic.to_string()))?,
            op_str: insn.op_str().map(str::to_string),
            operands: detail
                .arch_detail()
                .mips()
                .expect("All decompiled instructions should be MIPS")
                .operands()
                .collect(),
            new_line: false,
            target: JumpKind::from((insn, detail)),
        })
    }
}
