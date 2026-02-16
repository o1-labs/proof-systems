//! Keccak hash module
pub mod constants;
pub mod witness;

use crate::circuits::expr::constraints::ExprOps;
use ark_ff::PrimeField;

use self::constants::{DIM, QUARTERS, RATE_IN_BYTES, ROUNDS};
use super::super::berkeley_columns::BerkeleyChallengeTerm;

#[macro_export]
macro_rules! grid {
    (5, $v:expr) => {{
        |x: usize| $v[x].clone()
    }};
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
/// Note that the order of the indexing is `[y][x]` to match the encoding of the witness algorithm
pub const OFF: [[u64; DIM]; DIM] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

/// Contains the 24 round constants for Keccak
pub const RC: [u64; ROUNDS] = [
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

/// Naive Keccak structure
pub struct Keccak {}

/// Trait containing common operations for optimized Keccak
impl Keccak {
    /// Composes a vector of 4 dense quarters into the dense full u64 word
    pub fn compose(quarters: &[u64]) -> u64 {
        quarters[0] + (1 << 16) * quarters[1] + (1 << 32) * quarters[2] + (1 << 48) * quarters[3]
    }
    /// Takes a dense u64 word and decomposes it into a vector of 4 dense quarters.
    /// The first element of the vector corresponds to the 16 least significant bits.
    pub fn decompose(word: u64) -> Vec<u64> {
        vec![
            word % (1 << 16),
            (word / (1 << 16)) % (1 << 16),
            (word / (1 << 32)) % (1 << 16),
            (word / (1 << 48)) % (1 << 16),
        ]
    }

    /// Expands a quarter of a word into the sparse representation as a u64
    pub fn expand(quarter: u64) -> u64 {
        u64::from_str_radix(&format!("{:b}", quarter), 16).unwrap()
    }

    /// Expands a u64 word into a vector of 4 sparse u64 quarters
    pub fn expand_word<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(word: u64) -> Vec<T> {
        Self::decompose(word)
            .iter()
            .map(|q| T::literal(F::from(Self::expand(*q))))
            .collect::<Vec<T>>()
    }

    /// Returns the expansion of the 4 dense decomposed quarters of a word where
    /// the first expanded element corresponds to the 16 least significant bits of the word.
    pub fn sparse(word: u64) -> Vec<u64> {
        Self::decompose(word)
            .iter()
            .map(|q| Self::expand(*q))
            .collect::<Vec<u64>>()
    }
    /// From each quarter in sparse representation, it computes its 4 resets.
    /// The resulting vector contains 4 times as many elements as the input.
    /// The output is placed in the vector as [shift0, shift1, shift2, shift3]
    pub fn shift(state: &[u64]) -> Vec<u64> {
        let n = state.len();
        let mut shifts = vec![0; QUARTERS * n];
        let aux = Self::expand(0xFFFF);
        for (i, term) in state.iter().enumerate() {
            shifts[i] = aux & term; // shift0 = reset0
            shifts[n + i] = ((aux << 1) & term) / 2; // shift1 = reset1/2
            shifts[2 * n + i] = ((aux << 2) & term) / 4; // shift2 = reset2/4
            shifts[3 * n + i] = ((aux << 3) & term) / 8; // shift3 = reset3/8
        }
        shifts
    }

    /// From a vector of shifts, resets the underlying value returning only shift0
    /// Note that shifts is always a vector whose length is a multiple of 4.
    pub fn reset(shifts: &[u64]) -> Vec<u64> {
        shifts[0..shifts.len() / QUARTERS].to_vec()
    }

    /// From a canonical expanded state, obtain the corresponding 16-bit dense terms
    pub fn collapse(state: &[u64]) -> Vec<u64> {
        state
            .iter()
            .map(|&reset| u64::from_str_radix(&format!("{:x}", reset), 2).unwrap())
            .collect::<Vec<u64>>()
    }

    /// Outputs the state into dense quarters of 16-bits each in little endian order
    pub fn quarters(state: &[u8]) -> Vec<u64> {
        let mut quarters = vec![];
        for pair in state.chunks(2) {
            quarters.push(u16::from_le_bytes([pair[0], pair[1]]) as u64);
        }
        quarters
    }

    /// On input a vector of 16-bit dense quarters, outputs a vector of 8-bit bytes in the right order for Keccak
    pub fn bytestring(dense: &[u64]) -> Vec<u64> {
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
    pub fn expand_state(state: &[u8]) -> Vec<u64> {
        let mut expanded = vec![];
        for pair in state.chunks(2) {
            let quarter = u16::from_le_bytes([pair[0], pair[1]]);
            expanded.push(Self::expand(quarter as u64));
        }
        expanded
    }

    /// On input a length, returns the smallest multiple of RATE_IN_BYTES that is greater than the bytelength.
    /// That means that if the input has a length that is a multiple of the RATE_IN_BYTES, then
    /// it needs to add one whole block of RATE_IN_BYTES bytes just for padding purposes.
    pub fn padded_length(bytelength: usize) -> usize {
        Self::num_blocks(bytelength) * RATE_IN_BYTES
    }

    /// Pads the message with the 10*1 rule until reaching a length that is a multiple of the rate
    pub fn pad(message: &[u8]) -> Vec<u8> {
        let msg_len = message.len();
        let pad_len = Self::padded_length(msg_len);
        let mut padded = vec![0; pad_len];
        for (i, byte) in message.iter().enumerate() {
            padded[i] = *byte;
        }
        padded[msg_len] = 0x01;
        padded[pad_len - 1] += 0x80;

        padded
    }

    /// Number of blocks to be absorbed on input a given preimage bytelength
    pub fn num_blocks(bytelength: usize) -> usize {
        bytelength / RATE_IN_BYTES + 1
    }
}

#[cfg(test)]
mod tests {

    use rand::{rngs::StdRng, thread_rng, Rng};
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    // Shows that the expansion of the 16-bit dense quarters into 64-bit sparse quarters
    // corresponds to the binary representation of the 16-bit dense quarter.
    fn test_bitwise_sparse_representation() {
        assert_eq!(Keccak::expand(0xFFFF), 0x1111111111111111);
        assert_eq!(Keccak::expand(0x0000), 0x0000000000000000);
        assert_eq!(Keccak::expand(0x1234), 0x0001001000110100)
    }

    #[test]
    // Tests that composing and decomposition are the inverse of each other,
    // and the order of the quarters is the desired one.
    fn test_compose_decompose() {
        let word: u64 = 0x70d324ac9215fd8e;
        let dense = Keccak::decompose(word);
        let expected_dense = [0xfd8e, 0x9215, 0x24ac, 0x70d3];
        for i in 0..QUARTERS {
            assert_eq!(dense[i], expected_dense[i]);
        }
        assert_eq!(word, Keccak::compose(&dense));
    }

    #[test]
    // Tests that expansion works as expected with one quarter word
    fn test_quarter_expansion() {
        let quarter: u16 = 0b01011010111011011; // 0xB5DB
        let expected_expansion = 0b0001000000010001000000010000000100010001000000010001000000010001; // 0x01011010111011011
        assert_eq!(expected_expansion, Keccak::expand(quarter as u64));
    }

    #[test]
    // Tests that expansion of decomposed quarters works as expected
    fn test_sparse() {
        let word: u64 = 0x1234567890abcdef;
        let sparse = Keccak::sparse(word);
        let expected_sparse: Vec<u64> = vec![
            0x1100110111101111, // 0xcdef
            0x1001000010101011, // 0x90ab
            0x0101011001111000, // 0x5678
            0x0001001000110100, // 0x1234
        ];
        for i in 0..QUARTERS {
            assert_eq!(sparse[i], expected_sparse[i]);
        }
    }

    #[test]
    // Tests that the shifts are computed correctly
    fn test_shifts() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let word: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let sparse = Keccak::sparse(word);
        let shifts = Keccak::shift(&sparse);
        for i in 0..QUARTERS {
            assert_eq!(
                sparse[i],
                shifts[i] + shifts[4 + i] * 2 + shifts[8 + i] * 4 + shifts[12 + i] * 8
            )
        }
    }

    #[test]
    // Checks that reset function returns shift0, as the first positions of the shifts vector
    fn test_reset() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let word: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let shifts = Keccak::shift(&Keccak::sparse(word));
        let reset = Keccak::reset(&shifts);
        assert_eq!(reset.len(), 4);
        assert_eq!(shifts.len(), 16);
        for i in 0..QUARTERS {
            assert_eq!(reset[i], shifts[i])
        }
    }

    #[test]
    // Checks that one can obtain the original word from the resets of the expanded word
    fn test_collapse() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let word: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let dense = Keccak::compose(&Keccak::collapse(&Keccak::reset(&Keccak::shift(
            &Keccak::sparse(word),
        ))));
        assert_eq!(word, dense);
    }

    #[test]
    // Checks that concatenating the maximum number of carries (15 per bit) result
    // in the same original dense word, and just one more carry results in a different word
    fn test_max_carries() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let word: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let carries = 0xEEEE;
        // add a few carry bits to the canonical representation
        let mut sparse = Keccak::sparse(word)
            .iter()
            .map(|x| *x + carries)
            .collect::<Vec<u64>>();
        let dense = Keccak::compose(&Keccak::collapse(&Keccak::reset(&Keccak::shift(&sparse))));
        assert_eq!(word, dense);

        sparse[0] += 1;
        let wrong_dense =
            Keccak::compose(&Keccak::collapse(&Keccak::reset(&Keccak::shift(&sparse))));
        assert_ne!(word, wrong_dense);
    }

    #[test]
    // Tests that the XOR can be represented in the 4i-th
    // positions of the addition of sparse representations
    fn test_sparse_xor() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let a: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let b: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let xor = a ^ b;

        let sparse_a = Keccak::sparse(a);
        let sparse_b = Keccak::sparse(b);

        // compute xor as sum of a and b
        let sparse_sum = sparse_a
            .iter()
            .zip(sparse_b.iter())
            .map(|(a, b)| a + b)
            .collect::<Vec<u64>>();
        let reset_sum = Keccak::reset(&Keccak::shift(&sparse_sum));

        assert_eq!(Keccak::sparse(xor), reset_sum);
    }

    #[test]
    // Tests that the AND can be represented in the (4i+1)-th positions of the
    // addition of canonical sparse representations
    fn test_sparse_and() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let a: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let b: u64 = rng.gen_range(0..2u128.pow(64)) as u64;
        let and = a & b;

        let sparse_a = Keccak::sparse(a);
        let sparse_b = Keccak::sparse(b);

        // compute and as carries of sum of a and b
        let sparse_sum = sparse_a
            .iter()
            .zip(sparse_b.iter())
            .map(|(a, b)| a + b)
            .collect::<Vec<u64>>();
        let carries_sum = &Keccak::shift(&sparse_sum)[4..8];

        assert_eq!(Keccak::sparse(and), carries_sum);
    }

    #[test]
    // Tests that the NOT can be represented as subtraction with the expansion of
    // the 16-bit dense quarter.
    fn test_sparse_not() {
        let seed: [u8; 32] = thread_rng().gen();
        eprintln!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let word = rng.gen_range(0..2u64.pow(16));
        let expanded = Keccak::expand(word);

        // compute not as subtraction with expand all ones
        let all_ones = 0xFFFF;
        let not = all_ones - word;
        let sparse_not = Keccak::expand(all_ones) - expanded;

        assert_eq!(not, Keccak::collapse(&[sparse_not])[0]);
    }

    #[test]
    // Checks that the padding length is correctly computed
    fn test_pad_length() {
        assert_eq!(Keccak::padded_length(0), RATE_IN_BYTES);
        assert_eq!(Keccak::padded_length(1), RATE_IN_BYTES);
        assert_eq!(Keccak::padded_length(RATE_IN_BYTES - 1), RATE_IN_BYTES);
        // If input is already a multiple of RATE bytes, it needs to add a whole new block just for padding
        assert_eq!(Keccak::padded_length(RATE_IN_BYTES), 2 * RATE_IN_BYTES);
        assert_eq!(
            Keccak::padded_length(RATE_IN_BYTES * 2 - 1),
            2 * RATE_IN_BYTES
        );
        assert_eq!(Keccak::padded_length(RATE_IN_BYTES * 2), 3 * RATE_IN_BYTES);
    }

    #[test]
    // Checks that the padding is correctly computed
    fn test_pad() {
        let message = vec![0xFF; RATE_IN_BYTES - 1];
        let padded = Keccak::pad(&message);
        assert_eq!(padded.len(), RATE_IN_BYTES);
        assert_eq!(padded[padded.len() - 1], 0x81);

        let message = vec![0x01; RATE_IN_BYTES];
        let padded = Keccak::pad(&message);
        assert_eq!(padded.len(), 2 * RATE_IN_BYTES);
        assert_eq!(padded[message.len()], 0x01);
        assert_eq!(padded[padded.len() - 1], 0x80);
    }
}
