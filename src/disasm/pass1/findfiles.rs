use crate::disasm::{instruction::Instruction, mipsvals::INS_NOP};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileBreak {
    Likely,
    Possible,
    Nope,
}

#[derive(Debug)]
pub struct FindFileState {
    nops: u8,
    jrra: JrraStatus,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum JrraStatus {
    Clear,
    Jrra,
    Delay,
    NopHold,
}

impl Default for FindFileState {
    fn default() -> Self {
        Self {
            nops: 0,
            jrra: JrraStatus::Clear,
        }
    }
}

impl FindFileState {
    // .text sections are padded to the nearest 16 byte boundry with nops/zeros
    pub fn find_file_gaps(&mut self, insn: &mut Instruction) {
        use JrraStatus::*;

        let is_nop = insn.id.0 == INS_NOP;
        let is_jrra = insn.jump.is_jrra();
        let aligned_insn = insn.vaddr % 0x10 == 0;

        insn.file_break = match (self.nops >= 2, aligned_insn, self.jrra) {
            (true, true, NopHold) => FileBreak::Likely,
            (true, true, _) => FileBreak::Possible,
            _ => FileBreak::Nope,
        };

        self.jrra = match (is_nop, is_jrra, self.jrra) {
            // nop + not Clear -> remember that there was a jr ra
            (true, _, NopHold) => NopHold,
            (true, _, Jrra) => NopHold,
            (true, _, Delay) => NopHold,
            // not nop + not jr ra + remembered jr ra -> forget jr ra
            (false, false, NopHold) => Clear,
            // not nop + jr ra + remembered jr ra -> new jr ra
            (false, true, NopHold) => Jrra,
            // jr ra delay slot state machine
            (_, true, _) => Jrra,
            (_, _, Jrra) => Delay,
            (_, _, Delay) => Clear,
            (_, _, Clear) => Clear,
        };

        self.nops = if is_nop { self.nops + 1 } else { 0 };
    }
}
