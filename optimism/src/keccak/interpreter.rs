//! This module defines the Keccak interpreter in charge of triggering the Keccak workflow

use ark_ff::{One, Zero};
use std::fmt::Debug;

/// This trait includes functionalities needed to obtain the variables of the Keccak circuit needed for constraints and witness
pub trait KeccakInterpreter<F: One + Debug + Zero> {
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone
        + Debug
        + One
        + Zero;
}
