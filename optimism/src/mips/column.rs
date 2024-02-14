pub(crate) const MIPS_HASH_COUNTER_OFFSET: usize = 80;
pub(crate) const MIPS_IS_SYSCALL_OFFSET: usize = 81;
pub(crate) const MIPS_BYTES_READ_OFFSET: usize = 82;
pub(crate) const MIPS_PREIMAGE_LEFT_OFFSET: usize = 83;
pub(crate) const MIPS_PREIMAGE_BYTES_OFFSET: usize = 84;
pub(crate) const MIPS_HAS_N_BYTES_OFFSET: usize = 88;
pub(crate) const MIPS_CHUNK_BYTES_LENGTH: usize = 4;

/// Abstract columns (or variables of our multi-variate polynomials) that will be used to
/// describe our constraints.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    // Can be seen as the abstract indexed variable X_{i}
    ScratchState(usize),
    InstructionCounter,
}
