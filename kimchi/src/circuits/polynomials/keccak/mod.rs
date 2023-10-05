//! Keccak hash module
pub mod circuitgates;
pub mod gadget;

pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;
pub const ROUNDS: usize = 24;
pub const RATE: usize = 1088 / 8;
pub const CAPACITY: usize = 512 / 8;
pub const KECCAK_COLS: usize = 2344;

use crate::circuits::expr::constraints::ExprOps;
use ark_ff::PrimeField;

#[macro_export]
macro_rules! state_from_vec {
    ($expr:expr) => {
        |i: usize, x: usize, y: usize, q: usize| {
            $expr[q + QUARTERS * (x + DIM * (y + DIM * i))].clone()
        }
    };
}

pub(crate) const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Takes a dense u64 word and decomposes it into a vector of 4 dense quarters
pub(crate) fn decompose(word: u64) -> Vec<u64> {
    vec![
        word % (1 << 16),
        (word / (1 << 16)) % (1 << 16),
        (word / (1 << 32)) % (1 << 16),
        (word / (1 << 48)) % (1 << 16),
    ]
}

/// Expands a quarter of a word into the sparse representation as a u64
pub(crate) fn expand(quarter: u64) -> u64 {
    u64::from_str_radix(&format!("{:b}", quarter), 16).unwrap()
}

pub(crate) fn expand_word<F: PrimeField, T: ExprOps<F>>(word: u64) -> Vec<T> {
    decompose(word)
        .iter()
        .map(|q| T::literal(F::from(expand(*q))))
        .collect::<Vec<T>>()
}
