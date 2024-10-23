use super::{
    interpreter::{
        SBInstruction, IInstruction, Instruction,
        Instruction::{SBType, IType, UJType, RType, SType, UType},
        RInstruction, SInstruction, UInstruction,
    },
    INSTRUCTION_SET_SIZE, SCRATCH_SIZE,
};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr},
};
use strum::EnumCount;

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
        match instr {
            RType(rtype) => SCRATCH_SIZE + 1 + rtype as usize,
            IType(itype) => SCRATCH_SIZE + 1 + RInstruction::COUNT + itype as usize,
            SType(stype) => {
                SCRATCH_SIZE + 1 + RInstruction::COUNT + IInstruction::COUNT + stype as usize
            }
            SBType(sbtype) => {
                SCRATCH_SIZE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + sbtype as usize
            }
            UType(utype) => {
                SCRATCH_SIZE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + utype as usize
            }
            UJType(ujtype) => {
                SCRATCH_SIZE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + UInstruction::COUNT
                    + ujtype as usize
            }
        }
    }
}

// FIXME: other challenges
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;
