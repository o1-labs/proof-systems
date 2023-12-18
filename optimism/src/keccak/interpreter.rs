/// Variants of Keccak steps available for the interpreter
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum KeccakStep {
    Sponge(Sponge),
    Round(u64),
}

/// Variants of Keccak sponges
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Sponge {
    Absorb(Absorb),
    Squeeze,
}

/// Order of absorb steps in the computation depending on the number of blocks to absorb
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Absorb {
    First,
    Middle,
    Last,
    FirstAndLast,
}

/// Interpreter for the Keccak hash function
pub trait KeccakInterpreter {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    // FIXME: read preimage from memory
    fn hash(&mut self, preimage: Vec<u8>);

    fn step(&mut self);

    fn set_flag_round(&mut self, round: u64);
    fn set_flag_absorb(&mut self, absorb: Absorb);
    fn set_flag_root(&mut self);
    fn set_flag_pad(&mut self);

    fn run_sponge(&mut self, sponge: Sponge);
    fn run_absorb(&mut self, absorb: Absorb);
    fn run_squeeze(&mut self);
    fn run_round(&mut self, round: u64);
    fn run_theta(&mut self, state_a: &[u64]) -> Vec<u64>;
    fn run_pirho(&mut self, state_e: &[u64]) -> Vec<u64>;
    fn run_chi(&mut self, state_b: &[u64]) -> Vec<u64>;
    fn run_iota(&mut self, state_f: &[u64], round: usize);
}
