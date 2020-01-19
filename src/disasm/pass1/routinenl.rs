use crate::disasm::{instruction::Instruction, pass1::JumpKind};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NLState {
    Clear,
    Delay,
    NewLine,
}

impl Default for NLState {
    fn default() -> Self {
        Self::Clear
    }
}

impl NLState {
    // shouldn't have a jump in the delay slot of a jump, as that is undefined in MIPS.
    // So, there's no worry about overlapping jump/branches... right?
    pub fn newline_between_routines(&mut self, insn: &mut Instruction) {
        use NLState::*;

        insn.new_line = *self == NewLine;

        *self = match self {
            Delay => NewLine,
            Clear | NewLine => match insn.jump {
                JumpKind::Jump(_) => Delay,
                JumpKind::JumpRegister(_) if insn.jump.is_jrra() => Delay,
                _ => Clear,
            },
        };
    }
}
