#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    ScratchState(usize),
    InstructionCounter,
    PreimageCounter,
    HashCounter,
}
