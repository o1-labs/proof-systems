use kimchi::circuits::{
    expr::{ConstantExpr, Expr},
    polynomials::keccak::constants::{DIM, KECCAK_COLS, QUARTERS},
};

use self::column::KeccakColumn;

pub mod column;
pub mod constraints;
pub mod environment;
pub mod interpreter;
pub mod lookups;
pub mod witness;

pub(crate) const HASH_BITLENGTH: usize = 256;
pub(crate) const HASH_BYTELENGTH: usize = HASH_BITLENGTH / 8;
pub(crate) const WORD_LENGTH_IN_BITS: usize = 64;
pub(crate) const _ZKVM_KECCAK_COLS: usize = KECCAK_COLS + 4 + 6;
pub(crate) const WORDS_IN_HASH: usize = HASH_BITLENGTH / WORD_LENGTH_IN_BITS;

pub(crate) type E<F> = Expr<ConstantExpr<F>, KeccakColumn>;

fn grid_index(size: usize, i: usize, y: usize, x: usize, q: usize) -> usize {
    match size {
        20 => q + QUARTERS * x,
        80 => q + QUARTERS * (x + DIM * i),
        100 => q + QUARTERS * (x + DIM * y),
        400 => q + QUARTERS * (x + DIM * (y + DIM * i)),
        _ => panic!("Invalid grid size"),
    }
}

pub(crate) trait BoolOps {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    fn boolean(x: Self::Variable) -> Self::Variable;

    fn not(x: Self::Variable) -> Self::Variable;

    fn is_one(x: Self::Variable) -> Self::Variable;

    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable;

    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable;

    fn either_false(x: Self::Variable, y: Self::Variable) -> Self::Variable;
}

pub(crate) trait ArithOps {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    fn constant(x: u64) -> Self::Variable;
    fn constant_field(x: Self::Fp) -> Self::Variable;

    fn zero() -> Self::Variable;
    fn one() -> Self::Variable;
    fn two() -> Self::Variable;

    fn two_pow(x: u64) -> Self::Variable;
}
