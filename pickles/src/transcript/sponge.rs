use circuit_construction::{Cs, Var, Constants};

use ark_ff::{FftField, PrimeField};

// TODO: these constants are currently hidden behind a trait
// which prevents their use with const-generics in current rust.
// We should change that...
const SPONGE_WIDTH: usize = 3;
const SPONGE_RATE: usize = 2;

/// Poseidon Sponge constrained inside a zero-knowledge proof
pub(super) struct ZkSponge<F: FftField + PrimeField> {
    state: [Var<F>; SPONGE_WIDTH],
    constants: Constants<F>,
}

impl <F: FftField + PrimeField> ZkSponge<F> {
    pub fn new(constants: Constants<F>) -> Self {
        ZkSponge{
            state: unimplemented!(),
            constants
        }
    }

    pub fn absorb<'b, C: Cs<F>, I: Iterator<Item = &'b Var<F>>>(&mut self, cs: &mut C, mut vars: I) {
        for var in vars {
            // TODO: implement
        }
    }
}