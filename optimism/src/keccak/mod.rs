use kimchi::circuits::{
    expr::{ConstantExpr, Expr},
    polynomials::keccak::constants::{DIM, KECCAK_COLS, QUARTERS, STATE_LEN},
};

use self::column::KeccakColumn;

pub mod column;
pub mod constraints;
pub mod environment;
pub mod interpreter;
pub mod lookups;
pub mod proof;
pub mod witness;

/// Desired output length of the hash in bits
pub(crate) const HASH_BITLENGTH: usize = 256;
/// Desired output length of the hash in bytes
pub(crate) const HASH_BYTELENGTH: usize = HASH_BITLENGTH / 8;
/// Length of each word in the Keccak state, in bits
pub(crate) const WORD_LENGTH_IN_BITS: usize = 64;
/// Number of columns required in the `curr` part of the witness
pub(crate) const ZKVM_KECCAK_COLS_CURR: usize = KECCAK_COLS + QUARTERS;
/// Number of columns required in the `next` part of the witness, corresponding to the output length
pub(crate) const ZKVM_KECCAK_COLS_NEXT: usize = STATE_LEN;
/// Number of words that fit in the hash digest
pub(crate) const WORDS_IN_HASH: usize = HASH_BITLENGTH / WORD_LENGTH_IN_BITS;

pub(crate) type E<F> = Expr<ConstantExpr<F>, KeccakColumn>;

// This function maps a 4D index into a 1D index depending on the length of the grid
fn grid_index(length: usize, i: usize, y: usize, x: usize, q: usize) -> usize {
    match length {
        5 => x,
        20 => q + QUARTERS * x,
        80 => q + QUARTERS * (x + DIM * i),
        100 => q + QUARTERS * (x + DIM * y),
        400 => q + QUARTERS * (x + DIM * (y + DIM * i)),
        _ => panic!("Invalid grid size"),
    }
}

/// This trait defines common boolean operations used in the Keccak circuit
pub(crate) trait BoolOps {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    /// Degree-2 variable encoding whether the input is a boolean value
    fn is_boolean(x: Self::Variable) -> Self::Variable;

    /// Degree-1 variable encoding the negation of the input
    /// Note: it only works as expected if the input is a boolean value
    fn not(x: Self::Variable) -> Self::Variable;

    /// Degree-1 variable encoding whether the input is the value one
    fn is_one(x: Self::Variable) -> Self::Variable;

    /// Degree-2 variable encoding whether the first input is nonzero.
    /// It requires the second input to be the multiplicative inverse of the first.
    /// Note: if the first input is zero, there is no multiplicative inverse.
    fn is_nonzero(x: Self::Variable, x_inv: Self::Variable) -> Self::Variable;

    /// Degree-1 variable encoding the XOR of two variables which should be boolean
    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable;

    /// Degree-1 variable encoding the OR of two variables, which should be boolean
    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable;

    /// Degree-2 variable encoding whether at least one of the two inputs is zero
    fn either_false(x: Self::Variable, y: Self::Variable) -> Self::Variable;
}

/// This trait defines common arithmetic operations used in the Keccak circuit
pub(crate) trait ArithOps {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    /// Creates a variable from a constant integer
    fn constant(x: u64) -> Self::Variable;
    /// Creates a variable from a constant field element
    fn constant_field(x: Self::Fp) -> Self::Variable;

    /// Returns a variable representing the value zero
    fn zero() -> Self::Variable;
    /// Returns a variable representing the value one
    fn one() -> Self::Variable;
    /// Returns a variable representing the value two
    fn two() -> Self::Variable;

    /// Returns a variable representing the value 2^x
    fn two_pow(x: u64) -> Self::Variable;
}
