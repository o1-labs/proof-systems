use std::collections::HashMap;

use crate::{
    keccak::column::{
        Absorbs::*,
        ColumnAlias as KeccakColumn,
        Sponges::*,
        Steps::{self, *},
        PAD_SUFFIX_LEN,
    },
    lookups::LookupTableIDs,
    Circuit, CircuitTrait,
};
use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::constants::{
    DIM, KECCAK_COLS, QUARTERS, RATE_IN_BYTES, STATE_LEN,
};
use kimchi_msm::witness::Witness;

use self::{column::ZKVM_KECCAK_COLS, environment::KeccakEnv};

pub mod column;
pub mod constraints;
pub mod environment;
pub mod folding;
pub mod interpreter;
#[cfg(test)]
pub mod tests;
pub mod witness;

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
    Selector(Selector),
    Constraint(Constraint),
    Lookup(LookupTableIDs),
}

/// All the names for selector misconfigurations of the Keccak circuit
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    NotBoolean(Steps),
    NotMutex,
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

#[allow(dead_code)]
/// The Keccak circuit
pub type KeccakCircuit<F> = Circuit<ZKVM_KECCAK_COLS, Steps, F>;

pub const STEPS: [Steps; 6] = [
    Round(0),
    Sponge(Absorb(First)),
    Sponge(Absorb(Middle)),
    Sponge(Absorb(Last)),
    Sponge(Absorb(Only)),
    Sponge(Squeeze),
];

#[allow(dead_code)]
impl<F: Field> CircuitTrait<ZKVM_KECCAK_COLS, Steps, F, KeccakEnv<F>> for KeccakCircuit<F> {
    fn new(domain_size: usize, _env: &mut KeccakEnv<F>) -> Self {
        let mut circuit = Self {
            domain_size,
            witness: HashMap::new(),
            constraints: Default::default(),
            lookups: Default::default(),
        };

        for step in STEPS {
            circuit.witness.insert(
                step,
                Witness {
                    cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
                },
            );
            circuit
                .constraints
                .insert(step, KeccakEnv::constraints_of(step));
            circuit.lookups.insert(step, KeccakEnv::lookups_of(step));
        }
        circuit
    }

    fn push_row(&mut self, step: Steps, row: &[F; ZKVM_KECCAK_COLS]) {
        // Make sure we are using the same round number to refer to round steps
        let mut step = step;
        if let Round(_) = step {
            step = Round(0);
        }
        self.witness.entry(step).and_modify(|wit| {
            for (i, value) in row.iter().enumerate() {
                if wit.cols[i].len() < wit.cols[i].capacity() {
                    wit.cols[i].push(*value);
                }
            }
        });
    }

    fn pad_rows(&mut self) {
        for step in STEPS {
            let rows_left =
                self.witness[&step].cols[0].capacity() - self.witness[&step].cols[0].len();
            for _ in 0..rows_left {
                self.push_row(step, &[F::zero(); ZKVM_KECCAK_COLS]);
            }
        }
    }

    fn reset(&mut self, step: Steps) {
        self.witness.insert(
            step,
            Witness {
                cols: Box::new(std::array::from_fn(|_| {
                    Vec::with_capacity(self.domain_size)
                })),
            },
        );
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
