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

    //////////////////////////
    // ARITHMETIC OPERATIONS //
    ///////////////////////////

    /// Creates a variable from a constant integer
    fn constant(x: u64) -> Self::Variable;

    /// Creates a variable from a constant field element
    fn constant_field(x: F) -> Self::Variable;

    /// Returns a variable representing the value zero
    fn zero() -> Self::Variable {
        Self::constant(0)
    }
    /// Returns a variable representing the value one
    fn one() -> Self::Variable {
        Self::constant(1)
    }
    /// Returns a variable representing the value two
    fn two() -> Self::Variable {
        Self::constant(2)
    }

    /// Returns a variable representing the value 2^x
    fn two_pow(x: u64) -> Self::Variable;
}
