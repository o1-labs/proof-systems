use crate::{
    interpreters::keccak::column::{ColumnAlias as KeccakColumn, Steps::*, PAD_SUFFIX_LEN},
    lookups::LookupTableIDs,
};
use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::constants::{
    DIM, KECCAK_COLS, QUARTERS, RATE_IN_BYTES, STATE_LEN,
};

pub mod column;
pub mod constraints;
pub mod environment;
pub mod helpers;
pub mod interpreter;
#[cfg(test)]
pub mod tests;
pub mod witness;

pub use column::{Absorbs, Sponges, Steps};

/// Desired output length of the hash in bits
pub(crate) const HASH_BITLENGTH: usize = 256;
/// Desired output length of the hash in bytes
pub(crate) const HASH_BYTELENGTH: usize = HASH_BITLENGTH / 8;
/// Length of each word in the Keccak state, in bits
pub(crate) const WORD_LENGTH_IN_BITS: usize = 64;
/// Number of columns required in the `curr` part of the witness
pub(crate) const ZKVM_KECCAK_COLS_CURR: usize = KECCAK_COLS;
/// Number of columns required in the `next` part of the witness, corresponding to the output length
pub(crate) const ZKVM_KECCAK_COLS_NEXT: usize = STATE_LEN;
/// Number of words that fit in the hash digest
pub(crate) const WORDS_IN_HASH: usize = HASH_BITLENGTH / WORD_LENGTH_IN_BITS;

/// Errors that can occur during the check of the witness
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Constraint(Constraint),
    Lookup(LookupTableIDs),
}

/// All the names for constraints involved in the Keccak circuit
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Constraint {
    BooleanityPadding(usize),
    AbsorbZeroPad(usize),
    AbsorbRootZero(usize),
    AbsorbXor(usize),
    AbsorbShifts(usize),
    PadAtEnd,
    PaddingSuffix(usize),
    SqueezeShifts(usize),
    ThetaWordC(usize),
    ThetaRotatedC(usize),
    ThetaQuotientC(usize),
    ThetaShiftsC(usize, usize),
    PiRhoWordE(usize, usize),
    PiRhoRotatedE(usize, usize),
    PiRhoShiftsE(usize, usize, usize),
    ChiShiftsB(usize, usize, usize),
    ChiShiftsSum(usize, usize, usize),
    IotaStateG(usize),
}

/// Standardizes a Keccak step to a common opcode
pub fn standardize(opcode: Steps) -> Steps {
    // Note that steps of execution are obtained from the constraints environment.
    // There, the round steps can be anything between 0 and 23 (for the 24 permutations).
    // Nonetheless, all of them contain the same set of constraints and lookups.
    // Therefore, we want to treat them as the same step when it comes to splitting the
    // circuit into multiple instances with shared behaviour. By default, we use `Round(0)`.
    if let Round(_) = opcode {
        Round(0)
    } else {
        opcode
    }
}

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

/// This function returns a vector of field elements that represent the 5 padding suffixes.
/// The first one uses at most 12 bytes, and the rest use at most 31 bytes.
pub fn pad_blocks<F: Field>(pad_bytelength: usize) -> [F; PAD_SUFFIX_LEN] {
    assert!(pad_bytelength > 0, "Padding length must be at least 1 byte");
    assert!(
        pad_bytelength <= 136,
        "Padding length must be at most 136 bytes",
    );
    // Blocks to store padding. The first one uses at most 12 bytes, and the rest use at most 31 bytes.
    let mut blocks = [F::zero(); PAD_SUFFIX_LEN];
    let mut pad = [F::zero(); RATE_IN_BYTES];
    pad[RATE_IN_BYTES - pad_bytelength] = F::one();
    pad[RATE_IN_BYTES - 1] += F::from(0x80u8);
    blocks[0] = pad
        .iter()
        .take(12)
        .fold(F::zero(), |acc, x| acc * F::from(256u32) + *x);
    for (i, block) in blocks.iter_mut().enumerate().take(5).skip(1) {
        // take 31 elements from pad, starting at 12 + (i - 1) * 31 and fold them into a single Fp
        *block = pad
            .iter()
            .skip(12 + (i - 1) * 31)
            .take(31)
            .fold(F::zero(), |acc, x| acc * F::from(256u32) + *x);
    }
    blocks
}
