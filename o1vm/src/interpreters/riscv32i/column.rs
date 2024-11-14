use super::{INSTRUCTION_SET_SIZE, SCRATCH_SIZE};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Column {
    ScratchState(usize),
    InstructionCounter,
    Selector(usize),
}

impl From<Column> for usize {
    fn from(col: Column) -> usize {
        match col {
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

// FIXME: use other challenges, not Berkeley.
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;
