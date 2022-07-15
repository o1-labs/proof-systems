use circuit_construction::{Constants, Cs, Var};

use ark_ff::{FftField, PrimeField};

// DISCUSS: these constants are currently hidden behind a trait
// which prevents their use with const-generics in current rust.
// We should change that...
const SPONGE_WIDTH: usize = 3;
const SPONGE_RATE: usize = 2;

/// Poseidon Sponge constrained inside a zero-knowledge proof
///
/// See "oracle" crate for the "plaintext implementation"
///
pub struct VarSponge<F: FftField + PrimeField> {
    state: [Var<F>; SPONGE_WIDTH],
    constants: Constants<F>,
}

impl<F: FftField + PrimeField> VarSponge<F> {
    pub fn new(constants: Constants<F>) -> Self {
        VarSponge {
            state: unimplemented!(),
            constants,
        }
    }

    pub fn absorb<'b, C: Cs<F>, T: Absorb<F>>(&mut self, cs: &mut C, val: &T) {
        val.absorb(cs, self);
    }

    pub fn challenge<C: Cs<F>, T: Challenge<F>>(&mut self, cs: &mut C) -> T {
        T::generate(cs, self)
    }
}

/// Describes a type which can be "squeezed" (generated) from the sponge
pub trait Challenge<F: FftField + PrimeField> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self;
}

// Can generate a variable from the same field
impl<F: FftField + PrimeField> Challenge<F> for Var<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        unimplemented!()
    }
}

/// Describes a type which can be "absorbed" into a sponge over a given field
pub trait Absorb<F: FftField + PrimeField> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>);
}

// Can absorb a slice of absorbable elements
impl<F: FftField + PrimeField, T: Absorb<F>> Absorb<F> for [T] {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        self.iter().for_each(|c| c.absorb(cs, sponge))
    }
}

// Can absorb a fixed length array of absorbable elements
impl<F: FftField + PrimeField, T: Absorb<F>, const N: usize> Absorb<F> for [T; N] {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        let slice: &[T] = &self[..];
        slice.absorb(cs, sponge)
    }
}

// Can absorb a variable from the same field
impl<F: FftField + PrimeField> Absorb<F> for Var<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        unimplemented!()
    }
}
