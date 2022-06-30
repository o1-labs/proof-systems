use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use super::Bits;

use crate::context::{FromPublic, Public, ToPublic};
use crate::transcript::{Challenge, VarSponge};

/// A challenge which is a sequence of bits: b_0, ..., b_l representing: \sum_i 2^i b_i
pub struct FieldChallenge<F: FftField + PrimeField> {
    inner: Bits<F>,
}

/// A bit challenge is already in "field" format (no conversion)
impl<F: FftField + PrimeField> Into<Var<F>> for FieldChallenge<F> {
    fn into(self) -> Var<F> {
        self.inner.bits
    }
}

impl<F: FftField + PrimeField> Challenge<F> for FieldChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        Self {
            inner: Bits::generate(cs, sponge),
        }
    }
}

impl<F: FftField + PrimeField> ToPublic<F> for FieldChallenge<F> {
    fn to_public(&self) -> Vec<Public<F>> {
        self.inner.to_public()
    }
}

impl<Fq: FftField + PrimeField, Fr: FftField + PrimeField> FromPublic<Fq, Fr>
    for FieldChallenge<Fr>
{
    type Error = ();

    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fq>>>(
        cs: &mut C,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        Bits::from_public(cs, inputs).map(|inner| Self { inner })
    }
}
