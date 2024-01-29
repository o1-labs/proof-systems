pub(crate) const MIPS_BYTES_READ_OFFSET: usize = 80;
pub(crate) const MIPS_PREIMAGE_LEFT_OFFSET: usize = 81;
pub(crate) const MIPS_PREIMAGE_BYTES_OFFSET: usize = 82;
pub(crate) const MIPS_HAS_N_BYTES_OFFSET: usize = 86;
pub(crate) const MIPS_HASH_COUNTER_OFFSET: usize = 90;
pub(crate) const MIPS_CHUNK_BYTES_LENGTH: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    ScratchState(usize),
    InstructionCounter,
}
