use crate::mips::{
    witness::SCRATCH_SIZE,
    Instruction,
    Instruction::{IType, JType, RType},
};
use kimchi_msm::{
    columns::{Column, ColumnIndexer},
    witness::Witness,
};
use std::ops::{Index, IndexMut};
use strum::EnumCount;

use super::{ITypeInstruction, JTypeInstruction, RTypeInstruction};

pub(crate) const MIPS_HASH_COUNTER_OFFSET: usize = 80;
pub(crate) const MIPS_IS_SYSCALL_OFFSET: usize = 81;
pub(crate) const MIPS_READING_PREIMAGE_OFFSET: usize = 82;
pub(crate) const MIPS_BYTES_READ_OFFSET: usize = 83;
pub(crate) const MIPS_PREIMAGE_LEFT_OFFSET: usize = 84;
pub(crate) const MIPS_PREIMAGE_BYTES_OFFSET: usize = 85;
pub(crate) const MIPS_HAS_N_BYTES_OFFSET: usize = 89;
pub(crate) const MIPS_CHUNK_BYTES_LENGTH: usize = 4;

/// Abstract columns (or variables of our multi-variate polynomials) that will be used to
/// describe our constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ColumnAlias {
    // Can be seen as the abstract indexed variable X_{i}
    ScratchState(usize),
    InstructionCounter,
    Selector(Instruction),
}

/// The columns used by the MIPS circuit.
/// The MIPS circuit is split into three main opcodes: RType, JType, IType.
/// The columns are shared between different instruction types.
/// (the total number of columns refers to the maximum of columns used by each mode)
impl ColumnAlias {
    pub fn ix(&self) -> usize {
        // Note that SCRATCH_SIZE + 1 is for the error
        match *self {
            ColumnAlias::ScratchState(i) => {
                assert!(i < SCRATCH_SIZE);
                i
            }
            ColumnAlias::InstructionCounter => SCRATCH_SIZE,
            ColumnAlias::Selector(instruction) => match instruction {
                RType(rtype) => SCRATCH_SIZE + 2 + rtype as usize,
                JType(jtype) => SCRATCH_SIZE + 2 + RTypeInstruction::COUNT + jtype as usize,
                IType(itype) => {
                    SCRATCH_SIZE
                        + 2
                        + RTypeInstruction::COUNT
                        + JTypeInstruction::COUNT
                        + itype as usize
                }
            },
        }
    }
}

/// Represents one line of the execution trace of the virtual machine
/// It does contain
/// [MIPS_SELECTORS_LENGTH] columns for the instruction selectors
/// + [SCRATCH_SIZE] columns
/// + 2 additional columns to keep track of the instruction index and one for the system error code.
/// The columns are, in order,
/// - the 32 general purpose registers
/// - the low and hi registers used by some arithmetic instructions
/// - the current instruction pointer
/// - the next instruction pointer
/// - the heap pointer
/// - the preimage key, splitted in 8 consecutive columns representing 4 bytes
/// of the 32 bytes long preimage key
/// - the preimage offset, i.e. the number of bytes that have been read for the
/// currently processing preimage
/// - `[SCRATCH_SIZE] - 46` intermediate columns that can be used by the
/// instruction set
/// - the hash counter
/// - the flag to indicate if the current instruction is a preimage syscall
/// - the flag to indicate if the current instruction is reading a preimage
/// - the number of bytes read so far for the current preimage
/// - how many bytes are left to be read for the current preimage
/// - the (at most) 4 bytes of the preimage key that are currently being processed
/// - 4 helpers to check if at least n bytes were read in the current row
pub type MIPSWitness<T> = Witness<MIPS_COLUMNS, T>;

pub const MIPS_COLUMNS: usize = SCRATCH_SIZE + 2 + MIPS_SELECTORS_LENGTH;
pub const MIPS_SELECTORS_LENGTH: usize =
    RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT;

impl<T: Clone> Index<ColumnAlias> for MIPSWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    fn index(&self, index: ColumnAlias) -> &Self::Output {
        &self.cols[index.ix()]
    }
}

impl<T: Clone> IndexMut<ColumnAlias> for MIPSWitness<T> {
    fn index_mut(&mut self, index: ColumnAlias) -> &mut Self::Output {
        &mut self.cols[index.ix()]
    }
}

impl ColumnIndexer for ColumnAlias {
    const COL_N: usize = MIPS_COLUMNS;
    fn to_column(self) -> Column {
        // TODO: what happens with error? It does not have a corresponding alias
        Column::X(self.ix())
    }
}
