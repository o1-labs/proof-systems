use crate::mips::keccak::column::KeccakColumn;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    ScratchState(usize),
    KeccakState(KeccakColumn),
}
