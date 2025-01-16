use super::{
    interpreter::{
        IInstruction,
        Instruction::{self, IType, MType, RType, SBType, SType, SyscallType, UJType, UType},
        RInstruction, SBInstruction, SInstruction, SyscallInstruction, UInstruction, UJInstruction,
    },
    INSTRUCTION_SET_SIZE, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE,
};
use kimchi::circuits::{
    berkeley_columns::BerkeleyChallengeTerm,
    expr::{ConstantExpr, Expr},
};
use strum::EnumCount;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Column {
    ScratchState(usize),
    ScratchStateInverse(usize),
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
            Column::ScratchStateInverse(i) => {
                assert!(i < SCRATCH_SIZE_INVERSE);
                SCRATCH_SIZE + i
            }
            Column::InstructionCounter => SCRATCH_SIZE + SCRATCH_SIZE_INVERSE,
            Column::Selector(s) => {
                assert!(
                    s < INSTRUCTION_SET_SIZE,
                    "There is only {INSTRUCTION_SET_SIZE}"
                );
                SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 1 + s
            }
        }
    }
}

impl From<Instruction> for usize {
    fn from(instr: Instruction) -> usize {
        match instr {
            RType(rtype) => SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 1 + rtype as usize,
            IType(itype) => {
                SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 1 + RInstruction::COUNT + itype as usize
            }
            SType(stype) => {
                SCRATCH_SIZE
                    + SCRATCH_SIZE_INVERSE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + stype as usize
            }
            SBType(sbtype) => {
                SCRATCH_SIZE
                    + SCRATCH_SIZE_INVERSE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + sbtype as usize
            }
            UType(utype) => {
                SCRATCH_SIZE
                    + SCRATCH_SIZE_INVERSE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + utype as usize
            }
            UJType(ujtype) => {
                SCRATCH_SIZE
                    + SCRATCH_SIZE_INVERSE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + UInstruction::COUNT
                    + ujtype as usize
            }
            SyscallType(syscalltype) => {
                SCRATCH_SIZE
                    + SCRATCH_SIZE_INVERSE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + UInstruction::COUNT
                    + UJInstruction::COUNT
                    + syscalltype as usize
            }
            MType(mtype) => {
                SCRATCH_SIZE
                    + SCRATCH_SIZE_INVERSE
                    + 1
                    + RInstruction::COUNT
                    + IInstruction::COUNT
                    + SInstruction::COUNT
                    + SBInstruction::COUNT
                    + UInstruction::COUNT
                    + UJInstruction::COUNT
                    + SyscallInstruction::COUNT
                    + mtype as usize
            }
        }
    }
}

// FIXME: use other challenges, not Berkeley.
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;
