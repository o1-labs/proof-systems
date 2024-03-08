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

    ////////////////////////
    // BOOLEAN OPERATIONS //
    ////////////////////////

    /// Degree-2 variable encoding whether the input is a boolean value (0 = yes)
    fn is_boolean(x: Self::Variable) -> Self::Variable {
        x.clone() * (x - Self::Variable::one())
    }

    /// Degree-1 variable encoding the negation of the input
    /// Note: it only works as expected if the input is a boolean value
    fn not(x: Self::Variable) -> Self::Variable {
        Self::Variable::one() - x
    }

    /// Degree-1 variable encoding whether the input is the value one (0 = yes)
    fn is_one(x: Self::Variable) -> Self::Variable {
        Self::not(x)
    }

    /// Degree-2 variable encoding whether the first input is nonzero (0 = yes).
    /// It requires the second input to be the multiplicative inverse of the first.
    /// Note: if the first input is zero, there is no multiplicative inverse.
    fn is_nonzero(x: Self::Variable, x_inv: Self::Variable) -> Self::Variable {
        Self::is_one(x * x_inv)
    }

    /// Degree-1 variable encoding the XOR of two variables which should be boolean (1 = true)
    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - Self::constant(2) * x * y
    }

    /// Degree-1 variable encoding the OR of two variables, which should be boolean (1 = true)
    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - x * y
    }

    /// Degree-2 variable encoding whether at least one of the two inputs is zero (0 = yes)
    fn either_zero(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x * y
    }

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
