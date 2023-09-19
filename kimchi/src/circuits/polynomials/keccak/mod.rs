//! Keccak hash module
pub mod circuitgates;
pub mod gadget;

pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;
pub const ROUNDS: usize = 24;
pub const RATE: usize = 136;

use crate::circuits::expr::constraints::ExprOps;
use ark_ff::PrimeField;

pub const RC: [u64; 24] = [
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

pub(crate) fn expand<F: PrimeField, T: ExprOps<F>>(word: u64) -> Vec<T> {
    format!("{:064b}", word)
        .chars()
        .collect::<Vec<char>>()
        .chunks(16)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .iter()
        .map(|c| T::literal(F::from(u64::from_str_radix(c, 16).unwrap())))
        .collect::<Vec<T>>()
}
