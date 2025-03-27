use crate::{
    interpreters::mips::Instruction::{self, IType, JType, RType},
    RelationColumnType,
};
use kimchi_msm::{
    columns::{Column, ColumnIndexer},
    witness::Witness,
};
use std::ops::{Index, IndexMut};
use strum::EnumCount;

use super::{ITypeInstruction, JTypeInstruction, RTypeInstruction};

pub(crate) const SCRATCH_SIZE_WITHOUT_KECCAK: usize = 45;
/// The number of hashes performed so far in the block
pub(crate) const MIPS_HASH_COUNTER_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK;
/// The number of bytes of the preimage that have been read so far in this hash
pub(crate) const MIPS_BYTE_COUNTER_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 1;
/// A flag indicating whether the preimage has been read fully or not
pub(crate) const MIPS_END_OF_PREIMAGE_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 2;
/// The number of preimage bytes processed in this step
pub(crate) const MIPS_NUM_BYTES_READ_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 3;
/// The at most 4-byte chunk of the preimage that has been read in this step.
/// Contains a field element of at most 4 bytes.
pub(crate) const MIPS_PREIMAGE_CHUNK_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 4;
/// The at most 4-bytes of the preimage that are currently being processed
/// Consists of 4 field elements of at most 1 byte each.
pub(crate) const MIPS_PREIMAGE_BYTES_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 5;
/// The at most 4-bytes of the length that are currently being processed
pub(crate) const MIPS_LENGTH_BYTES_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 5 + 4;
/// Flags indicating whether at least N bytes have been processed in this step
pub(crate) const MIPS_HAS_N_BYTES_OFF: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 5 + 4 + 4;
/// The maximum size of a chunk (4 bytes)
pub(crate) const MIPS_CHUNK_BYTES_LEN: usize = 4;
/// The location of the preimage key as a field element of 248bits
pub(crate) const MIPS_PREIMAGE_KEY: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 5 + 4 + 4 + 4;

// MIPS + hash_counter + byte_counter + eof + num_bytes_read + chunk + bytes
// + length + has_n_bytes + chunk_bytes + preimage
pub const SCRATCH_SIZE: usize = SCRATCH_SIZE_WITHOUT_KECCAK + 5 + 4 + 4 + 4 + 1;

/// Number of columns used by the MIPS interpreter to keep values to be
/// inverted.
pub const SCRATCH_SIZE_INVERSE: usize = 12;

/// The number of columns used for relation witness in the MIPS circuit
pub const N_MIPS_REL_COLS: usize = SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 2;

/// The number of witness columns used to store the instruction selectors.
/// NOTE: The +1 is coming from the NoOp instruction.
pub const N_MIPS_SEL_COLS: usize =
    RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT + 1;

/// All the witness columns used in MIPS
pub const N_MIPS_COLS: usize = N_MIPS_REL_COLS + N_MIPS_SEL_COLS;

/// Abstract columns (or variables of our multi-variate polynomials) that will
/// be used to describe our constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnAlias {
    // Can be seen as the abstract indexed variable X_{i}
    ScratchState(usize),
    // A column whose value needs to be inverted in the final witness.
    // We're keeping a separate column to perform a batch inversion at the end.
    ScratchStateInverse(usize),
    InstructionCounter,
    Selector(usize),
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
            ColumnAlias::ScratchStateInverse(i) => {
                assert!(i < SCRATCH_SIZE_INVERSE);
                SCRATCH_SIZE + i
            }
            ColumnAlias::InstructionCounter => SCRATCH_SIZE + SCRATCH_SIZE_INVERSE,
            ColumnAlias::Selector(s) => SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 1 + s,
        }
    }
}

/// Returns the corresponding index of the corresponding DynamicSelector column.
impl From<Instruction> for usize {
    fn from(instr: Instruction) -> usize {
        match instr {
            RType(rtype) => N_MIPS_REL_COLS + rtype as usize,
            JType(jtype) => N_MIPS_REL_COLS + RTypeInstruction::COUNT + jtype as usize,
            IType(itype) => {
                N_MIPS_REL_COLS + RTypeInstruction::COUNT + JTypeInstruction::COUNT + itype as usize
            }
            Instruction::NoOp => {
                N_MIPS_REL_COLS
                    + RTypeInstruction::COUNT
                    + JTypeInstruction::COUNT
                    + ITypeInstruction::COUNT
            }
        }
    }
}

/// Represents one line of the execution trace of the virtual machine
/// It contains
/// + [SCRATCH_SIZE] columns
/// + 1 column to keep track of the instruction index
/// + 1 column for the system error code
/// + [N_MIPS_SEL_COLS]  columns for the instruction selectors.
///   The columns are, in order,
/// - the 32 general purpose registers
/// - the low and hi registers used by some arithmetic instructions
/// - the current instruction pointer
/// - the next instruction pointer
/// - the heap pointer
/// - the preimage key, split in 8 consecutive columns representing 4 bytes
///   of the 32 bytes long preimage key
/// - the preimage offset, i.e. the number of bytes that have been read for the
///   currently processing preimage
/// - `[SCRATCH_SIZE] - 46` intermediate columns that can be used by the
///   instruction set
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

impl ColumnIndexer<RelationColumnType> for ColumnAlias {
    const N_COL: usize = N_MIPS_COLS;

    fn to_column(self) -> Column<RelationColumnType> {
        match self {
            Self::ScratchState(ss) => {
                assert!(
                    ss < SCRATCH_SIZE,
                    "The maximum index is {}, got {}",
                    SCRATCH_SIZE,
                    ss
                );
                Column::Relation(RelationColumnType::Scratch(ss))
            }
            Self::ScratchStateInverse(ss) => {
                assert!(
                    ss < SCRATCH_SIZE_INVERSE,
                    "The maximum index is {}, got {}",
                    SCRATCH_SIZE_INVERSE,
                    ss
                );
                Column::Relation(RelationColumnType::ScratchInverse(ss))
            }
            Self::InstructionCounter => Column::Relation(RelationColumnType::InstructionCounter),
            // TODO: what happens with error? It does not have a corresponding alias
            Self::Selector(s) => {
                assert!(
                    s < N_MIPS_SEL_COLS,
                    "The maximum index is {}, got {}",
                    N_MIPS_SEL_COLS,
                    s
                );
                Column::DynamicSelector(s)
            }
        }
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

impl ColumnIndexer<usize> for Instruction {
    const N_COL: usize = N_MIPS_REL_COLS + N_MIPS_SEL_COLS;
    fn to_column(self) -> Column<usize> {
        Column::DynamicSelector(usize::from(self) - N_MIPS_REL_COLS)
    }
}
