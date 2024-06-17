use crate::mips::{
    witness::SCRATCH_SIZE,
    Instruction::{self, IType, JType, RType},
};
use kimchi_msm::{
    columns::{Column, ColumnIndexer},
    witness::Witness,
};
use std::ops::{Index, IndexMut};
use strum::EnumCount;

use super::{ITypeInstruction, JTypeInstruction, RTypeInstruction};

/// The number of hashes performed so far in the block
pub(crate) const MIPS_HASH_COUNTER_OFF: usize = 80;
/// The number of bytes of the preimage that have been read so far in this hash
pub(crate) const MIPS_BYTE_COUNTER_OFF: usize = 81;
/// A flag indicating whether the preimage has been read fully or not
pub(crate) const MIPS_END_OF_PREIMAGE_OFF: usize = 82;
/// The number of preimage bytes processed in this step
pub(crate) const MIPS_NUM_BYTES_READ_OFF: usize = 83;
/// The at most 4-byte chunk of the preimage that has been read in this step.
/// Contains a field element of at most 4 bytes.
pub(crate) const MIPS_PREIMAGE_CHUNK_OFF: usize = 84;
/// The at most 4-bytes of the preimage that are currently being processed
/// Consists of 4 field elements of at most 1 byte each.
pub(crate) const MIPS_PREIMAGE_BYTES_OFF: usize = 85;
/// The at most 4-bytes of the length that are currently being processed
pub(crate) const MIPS_LENGTH_BYTES_OFF: usize = 89;
/// Flags indicating whether at least N bytes have been processed in this step
pub(crate) const MIPS_HAS_N_BYTES_OFF: usize = 93;
/// The maximum size of a chunk (4 bytes)
pub(crate) const MIPS_CHUNK_BYTES_LEN: usize = 4;

/// The number of columns used for relation witness in the MIPS circuit
pub const N_MIPS_REL_COLS: usize = SCRATCH_SIZE + 2;

/// The number of witness columns used to store the instruction selectors.
pub const N_MIPS_SEL_COLS: usize =
    RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT;

/// All the witness columns used in MIPS
pub const N_MIPS_COLS: usize = N_MIPS_REL_COLS + N_MIPS_SEL_COLS;

/// Abstract columns (or variables of our multi-variate polynomials) that will
/// be used to describe our constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnAlias {
    // Can be seen as the abstract indexed variable X_{i}
    ScratchState(usize),
    InstructionCounter,
}

/// The columns used by the MIPS circuit. The MIPS circuit is split into three
/// main opcodes: RType, JType, IType. The columns are shared between different
/// instruction types. (the total number of columns refers to the maximum of
/// columns used by each mode)
impl From<ColumnAlias> for usize {
    fn from(alias: ColumnAlias) -> usize {
        // Note that SCRATCH_SIZE + 1 is for the error
        match alias {
            ColumnAlias::ScratchState(i) => {
                assert!(i < SCRATCH_SIZE);
                i
            }
            ColumnAlias::InstructionCounter => SCRATCH_SIZE,
        }
    }
}

/// Returns the corresponding index of the corresponding DynamicSelector column.
impl From<Instruction> for usize {
    fn from(instr: Instruction) -> usize {
        match instr {
            RType(rtype) => rtype as usize,
            JType(jtype) => RTypeInstruction::COUNT + jtype as usize,
            IType(itype) => RTypeInstruction::COUNT + JTypeInstruction::COUNT + itype as usize,
        }
    }
}

/// Represents one line of the execution trace of the virtual machine It does
/// contain [N_MIPS_SEL_COLS] columns for the instruction selectors
/// + [SCRATCH_SIZE] columns
/// + 2 additional columns to keep track of the instruction index and one for
/// the system error code. The columns are, in order,
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
/// - the (at most) 4 bytes of the preimage key that are currently being
///   processed
/// - 4 helpers to check if at least n bytes were read in the current row
pub type MIPSWitness<T> = Witness<N_MIPS_COLS, T>;

// IMPLEMENTATIONS FOR COLUMN ALIAS

impl<T: Clone> Index<ColumnAlias> for MIPSWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    fn index(&self, index: ColumnAlias) -> &Self::Output {
        &self.cols[usize::from(index)]
    }
}

impl<T: Clone> IndexMut<ColumnAlias> for MIPSWitness<T> {
    fn index_mut(&mut self, index: ColumnAlias) -> &mut Self::Output {
        &mut self.cols[usize::from(index)]
    }
}

impl ColumnIndexer for ColumnAlias {
    const N_COL: usize = N_MIPS_COLS;
    fn to_column(self) -> Column {
        // TODO: what happens with error? It does not have a corresponding alias
        Column::Relation(usize::from(self))
    }
}

// IMPLEMENTATIONS FOR SELECTOR

impl<T: Clone> Index<Instruction> for MIPSWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    fn index(&self, index: Instruction) -> &Self::Output {
        &self.cols[usize::from(index)]
    }
}

impl<T: Clone> IndexMut<Instruction> for MIPSWitness<T> {
    fn index_mut(&mut self, index: Instruction) -> &mut Self::Output {
        &mut self.cols[usize::from(index)]
    }
}

impl ColumnIndexer for Instruction {
    const N_COL: usize = N_MIPS_COLS;
    fn to_column(self) -> Column {
        // TODO: what happens with error? It does not have a corresponding alias
        Column::DynamicSelector(usize::from(self))
    }
}
