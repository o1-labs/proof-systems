use kimchi::circuits::expr::{ConstantExpr, Expr};

use crate::mips::column::Column;

pub mod column;
pub mod constraints;
pub mod environment;

pub(crate) const HASH_LENGTH_IN_BITS: usize = 256;
pub(crate) const WORD_LENGTH_IN_BITS: usize = 64;
pub(crate) const _ZKVM_KECCAK_COLS: usize = 1965 + 4 + 6;
pub(crate) const _RATE: usize = 1088;
pub(crate) const _RATE_IN_BYTES: usize = _RATE / 8;
pub(crate) const DIM: usize = 5;
pub(crate) const QUARTERS: usize = 4;
pub(crate) const WORDS_IN_HASH: usize = HASH_LENGTH_IN_BITS / WORD_LENGTH_IN_BITS;

pub(crate) type E<F> = Expr<ConstantExpr<F>, Column>;

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

    fn constant(x: Self::Fp) -> Self::Variable;

    fn two_pow(x: u64) -> Self::Variable;
}
