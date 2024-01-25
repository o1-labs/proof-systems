//! This module defines the Keccak interpreter in charge of triggering the Keccak workflow

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
    First,        // Also known as the root absorb
    Middle,       // Any other absorb
    Last,         // Also known as the padding absorb
    FirstAndLast, // In case there is only one block to absorb (preimage data is less than 136 bytes)
}

/// Interpreter for the Keccak hash function in charge of instantiating the Keccak environment.
pub trait KeccakInterpreter {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    /// Entrypoint for the interpreter. It executes one step of the Keccak circuit (one row),
    /// and updates the environment accordingly (including the witness and inter-step lookups).
    /// When it finishes, it updates the value of the current step, so that the next call to
    /// the `step()` function executes the next step.
    fn step(&mut self);

    /// Updates the witness corresponding to the `FlagRound` column with a value in [0..24)
    fn set_flag_round(&mut self, round: u64);
    /// Sets the witness corresponding to the `FlagSqueeze` column to 1
    fn set_flag_squeeze(&mut self);
    /// Sets the witness corresponding to the `FlagAbsorb` column to 1 and
    /// updates and any other sponge flag depending on the kind of absorb step (root, padding, both).
    fn set_flag_absorb(&mut self, absorb: Absorb);
    /// Sets the witness corresponding to the `FlagRoot` column to 1
    fn set_flag_root(&mut self);
    /// Sets the witness corresponding to the `FlagPad` column to 1, and updates the remaining columns
    /// related to padding flags such as `PadLength`, `InvPadLength`, `TwoToPad`, `PadBytesFlags`, and `PadSuffix`.
    fn set_flag_pad(&mut self);

    /// Assigns the witness values needed in a sponge step (absorb or squeeze)
    fn run_sponge(&mut self, sponge: Sponge);
    /// Assigns the witness values needed in an absorb step (root, padding, or middle)
    fn run_absorb(&mut self, absorb: Absorb);
    /// Assigns the witness values needed in a squeeze step
    fn run_squeeze(&mut self);
    /// Assigns the witness values needed in the round step for the given round index
    fn run_round(&mut self, round: u64);
    /// Assigns the witness values needed in the theta algorithm
    fn run_theta(&mut self, state_a: &[u64]) -> Vec<u64>;
    /// Assigns the witness values needed in the pirho algorithm
    fn run_pirho(&mut self, state_e: &[u64]) -> Vec<u64>;
    /// Assigns the witness values needed in the chi algorithm
    fn run_chi(&mut self, state_b: &[u64]) -> Vec<u64>;
    /// Assigns the witness values needed in the iota algorithm
    fn run_iota(&mut self, state_f: &[u64], round: usize) -> Vec<u64>;
}
