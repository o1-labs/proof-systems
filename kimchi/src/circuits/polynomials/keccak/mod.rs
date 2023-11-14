//! Keccak hash module
pub mod circuitgates;
pub mod gadget;
pub mod witness;

pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;
pub const ROUNDS: usize = 24;
pub const RATE: usize = 1088 / 8;
pub const CAPACITY: usize = 512 / 8;
pub const KECCAK_COLS: usize = 2344;

use crate::circuits::expr::constraints::ExprOps;
use ark_ff::PrimeField;

#[macro_export]
macro_rules! grid {
    (20, $v:expr) => {{
        |x: usize, q: usize| $v[q + QUARTERS * x].clone()
    }};
    (80, $v:expr) => {{
        |i: usize, x: usize, q: usize| $v[q + QUARTERS * (x + DIM * i)].clone()
    }};
    (100, $v:expr) => {{
        |y: usize, x: usize, q: usize| $v[q + QUARTERS * (x + DIM * y)].clone()
    }};
    (400, $v:expr) => {{
        |i: usize, y: usize, x: usize, q: usize| {
            $v[q + QUARTERS * (x + DIM * (y + DIM * i))].clone()
        }
    }};
}

/// Creates the 5x5 table of rotation bits for Keccak modulo 64
/// | x \ y |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 | 36 |  3 | 41 | 18 |
/// | 1     |  1 | 44 | 10 | 45 |  2 |
/// | 2     | 62 |  6 | 43 | 15 | 61 |
/// | 3     | 28 | 55 | 25 | 21 | 56 |
/// | 4     | 27 | 20 | 39 |  8 | 14 |
/// Note that the order of the indexing is [y][x] to match the encoding of the witness algorithm
pub(crate) const OFF: [[u64; DIM]; DIM] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

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

// Composes a vector of 4 dense quarters into the dense full u64 word
pub(crate) fn compose(quarters: &[u64]) -> u64 {
    quarters[0] + (1 << 16) * quarters[1] + (1 << 32) * quarters[2] + (1 << 48) * quarters[3]
}

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

/// Expands a u64 word into a vector of 4 sparse u64 quarters
pub(crate) fn expand_word<F: PrimeField, T: ExprOps<F>>(word: u64) -> Vec<T> {
    decompose(word)
        .iter()
        .map(|q| T::literal(F::from(expand(*q))))
        .collect::<Vec<T>>()
}

/// Pads the message with the 10*1 rule until reaching a length that is a multiple of the rate
pub(crate) fn pad(message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    padded.push(0x01);
    while padded.len() % 136 != 0 {
        padded.push(0x00);
    }
    let last = padded.len() - 1;
    padded[last] += 0x80;
    padded
}

/// From each quarter in sparse representation, it computes its 4 resets.
/// The resulting vector contains 4 times as many elements as the input.
/// The output is placed in the vector as [reset0, reset1, reset2, reset3]
pub(crate) fn shift(state: &[u64]) -> Vec<u64> {
    let mut shifts = vec![vec![]; 4];
    let aux = expand(0xFFFF);
    for term in state {
        shifts[0].push(aux & term); // shift0 = reset0
        shifts[1].push(((aux << 1) & term) / 2); // shift1 = reset1/2
        shifts[2].push(((aux << 2) & term) / 4); // shift2 = reset2/4
        shifts[3].push(((aux << 3) & term) / 8); // shift3 = reset3/8
    }
    shifts.iter().flatten().copied().collect()
}

/// From a vector of shifts, resets the underlying value returning only shift0
pub(crate) fn reset(shifts: &[u64]) -> Vec<u64> {
    shifts
        .iter()
        .copied()
        .take(shifts.len() / 4)
        .collect::<Vec<u64>>()
}

/// From a reset0 state, obtain the corresponding 16-bit dense terms
pub(crate) fn collapse(state: &[u64]) -> Vec<u64> {
    let mut dense = vec![];
    for reset in state {
        dense.push(u64::from_str_radix(&format!("{:x}", reset), 2).unwrap());
    }
    dense
}

/// Outputs the state into dense quarters of 16-bits each in little endian order
pub(crate) fn quarters(state: &[u8]) -> Vec<u64> {
    let mut quarters = vec![];
    for pair in state.chunks(2) {
        quarters.push(u16::from_le_bytes([pair[0], pair[1]]) as u64);
    }
    quarters
}

/// On input a vector of 16-bit dense quarters, outputs a vector of 8-bit bytes in the right order for Keccak
pub(crate) fn bytestring(dense: &[u64]) -> Vec<u64> {
    dense
        .iter()
        .map(|x| vec![x % 256, x / 256])
        .collect::<Vec<Vec<u64>>>()
        .iter()
        .flatten()
        .copied()
        .collect()
}

/// On input a 200-byte vector, generates a vector of 100 expanded quarters representing the 1600-bit state
pub(crate) fn expand_state(state: &[u8]) -> Vec<u64> {
    let mut expanded = vec![];
    for pair in state.chunks(2) {
        let quarter = u16::from_le_bytes([pair[0], pair[1]]);
        expanded.push(expand(quarter as u64));
    }
    expanded
}

/// On input a length, returns the smallest multiple of RATE that is greater than the bytelength
pub(crate) fn padded_length(bytelength: usize) -> usize {
    (bytelength / RATE + 1) * RATE
}
