use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use super::Bits;

use crate::context::{FromPublic, Public, ToPublic};
use crate::transcript::{Challenge, VarSponge};

/// A collection of CHALLENGE_LEN bits representing a GLV decomposition
pub struct GLVChallenge<F: FftField + PrimeField> {
    inner: Bits<F>,
}

impl<F: FftField + PrimeField> Challenge<F> for GLVChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        Self {
            inner: Bits::generate(cs, sponge),
        }
    }
}

impl<F: FftField + PrimeField> ToPublic<F> for GLVChallenge<F> {
    fn to_public(&self) -> Vec<Public<F>> {
        self.inner.to_public()
    }
}

impl<Fq: FftField + PrimeField, Fr: FftField + PrimeField> FromPublic<Fq, Fr> for GLVChallenge<Fr> {
    type Error = ();

    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fq>>>(
        cs: &mut C,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        Bits::from_public(cs, inputs).map(|inner| Self { inner })
    }
}

impl<F: FftField + PrimeField> GLVChallenge<F> {
    pub fn to_field<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        unimplemented!()
    }
}
