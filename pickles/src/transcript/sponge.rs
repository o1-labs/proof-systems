use circuit_construction::{Constants, Cs, Var};

use ark_ff::{FftField, FpParameters, PrimeField};

// TODO: these constants are currently hidden behind a trait
// which prevents their use with const-generics in current rust.
// We should change that...
const SPONGE_WIDTH: usize = 3;
const SPONGE_RATE: usize = 2;

/// Poseidon Sponge constrained inside a zero-knowledge proof
///
/// See "oracle" crate for the "plaintext implementation"
///
pub struct ZkSponge<F: FftField + PrimeField> {
    state: [Var<F>; SPONGE_WIDTH],
    constants: Constants<F>,
}

impl<F: FftField + PrimeField> ZkSponge<F> {
    pub fn new(constants: Constants<F>) -> Self {
        ZkSponge {
            state: unimplemented!(),
            constants,
        }
    }

    pub fn absorb<'b, C: Cs<F>>(
        &mut self,
        cs: &mut C,
        var: &Var<F>,
    ) {
        unimplemented!()
    }

    pub fn squeeze<C: Cs<F>>(&mut self, cs: &mut C) -> Var<F> {
        unimplemented!()
    }
}
