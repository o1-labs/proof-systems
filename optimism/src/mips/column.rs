pub(crate) const MIPS_HASH_COUNTER_OFFSET: usize = 80;
pub(crate) const MIPS_PREIMAGE_LEFT_OFFSET: usize = 81;
pub(crate) const _MIPS_PREIMAGE_CHUNKS_OFFSET: usize = 82;
pub(crate) const _MIPS_PREIMAGE_CHUNKS_LENGTH: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    ScratchState(usize),
    InstructionCounter,
}
