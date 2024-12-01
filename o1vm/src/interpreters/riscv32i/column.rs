use super::{
    interpreter::{
        IInstruction, Instruction,
        Instruction::{IType, RType, SBType, SType, SyscallType, UJType, UType},
        RInstruction, SBInstruction, SInstruction, UInstruction, UJInstruction,
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
    Error,
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
            Column::Error => SCRATCH_SIZE + 1,
            Column::Selector(s) => {
                assert!(
                    s < INSTRUCTION_SET_SIZE,
                    "There is only {INSTRUCTION_SET_SIZE}"
                );
                SCRATCH_SIZE + 2 + s
            }
        }
    }
}

impl From<Instruction> for usize {
    fn from(instr: Instruction) -> usize {
        match instr {
            RType(rtype) => SCRATCH_SIZE + 2 + rtype as usize,
            IType(itype) => SCRATCH_SIZE + 2 + RInstruction::COUNT + itype as usize,
            SType(stype) => {
                SCRATCH_SIZE + 2 + RInstruction::COUNT + IInstruction::COUNT + stype as usize
            }
            SBType(sbtype) => {
                SCRATCH_SIZE
                    + 2
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + sbtype as usize
            }
            UType(utype) => {
                SCRATCH_SIZE
                    + 2
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + utype as usize
            }
            UJType(ujtype) => {
                SCRATCH_SIZE
                    + 2
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + UInstruction::COUNT
                    + ujtype as usize
            }
            SyscallType(syscall) => {
                SCRATCH_SIZE
                    + 2
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + UInstruction::COUNT
                    + UJInstruction::COUNT
                    + syscall as usize
            }
        }
    }
}

// FIXME: other challenges
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;
