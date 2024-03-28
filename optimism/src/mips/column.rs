use kimchi::folding::expressions::FoldingColumnTrait;

use kimchi_msm::witness::Witness;

use super::witness::{INVERSE_SIZE, SCRATCH_SIZE};

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
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    // Can be seen as the abstract indexed variable X_{i}
    ScratchState(usize),
    InverseState(usize),
    InstructionCounter,
}

impl FoldingColumnTrait for Column {
    fn is_witness(&self) -> bool {
        // All MIPS columns are witness columns
        true
    }
}

/// Represents one line of the execution trace of the virtual machine
/// It does contain [SCRATCH_SIZE] columns + 2 additional columns to keep track
/// of the instruction index and one for the system error code.
/// The column are, in order,
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

pub const MIPS_COLUMNS: usize = SCRATCH_SIZE + INVERSE_SIZE + 2;

pub trait MIPSWitnessTrait<T> {
    fn scratch(&self) -> &[T];
    fn inverse(&self) -> &[T];
    fn instruction_counter(&self) -> &T;
    fn error(&mut self) -> &T;
}

impl<T: Clone> MIPSWitnessTrait<T> for MIPSWitness<T> {
    fn scratch(&self) -> &[T] {
        &self.cols[..SCRATCH_SIZE]
    }

    // TODO: remember to batch invert these columns before folding
    fn inverse(&self) -> &[T] {
        &self.cols[SCRATCH_SIZE..SCRATCH_SIZE + INVERSE_SIZE]
    }

    fn instruction_counter(&self) -> &T {
        &self.cols[SCRATCH_SIZE + INVERSE_SIZE]
    }

    fn error(&mut self) -> &T {
        &self.cols[SCRATCH_SIZE + INVERSE_SIZE + 1]
    }
}
