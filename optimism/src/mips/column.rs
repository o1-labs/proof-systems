/// Abstract columns (or variables of our multi-variate polynomials) that will be used to
/// describe our constraints.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Column {
    // Can be seen as the indexed variable X_{i}
    ScratchState(usize),
    InstructionCounter,
}
