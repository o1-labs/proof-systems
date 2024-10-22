use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr},
};

use super::{interpreter::Instruction, INSTRUCTION_SET_SIZE, SCRATCH_SIZE};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Column {
    ScratchState(usize),
    InstructionCounter,
    Selector(usize),
}

impl From<Column> for usize {
    fn from(alias: Column) -> usize {
        // Note that SCRATCH_SIZE + 1 is for the error
        match alias {
            Column::ScratchState(i) => {
                assert!(i < SCRATCH_SIZE);
                i
            }
            Column::InstructionCounter => SCRATCH_SIZE,
            Column::Selector(s) => {
                assert!(
                    s < INSTRUCTION_SET_SIZE,
                    "There is only {INSTRUCTION_SET_SIZE}"
                );
                SCRATCH_SIZE + 1 + s
            }
        }
    }
}

impl From<Instruction> for usize {
    fn from(instr: Instruction) -> usize {
        SCRATCH_SIZE + 1 + instr as usize
    }
}

// FIXME: other challenges
pub(crate) type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;
