use ark_ff::{FftField, PrimeField};

use circuit_construction::{Constants, Cs, Var};

use super::Bits;

use crate::context::{FromPublic, Pass, Public, ToPublic};
use crate::transcript::{Challenge, VarSponge};

/// A challenge which is a sequence of bits: b_0, ..., b_l representing: \sum_i 2^i b_i
pub struct FieldChallenge<F: FftField + PrimeField> {
    inner: Bits<F>,
}

impl<F: FftField + PrimeField> Challenge<F> for FieldChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        Self {
            inner: Bits::generate(cs, sponge),
        }
    }
}

/// A bit challenge is already in "field" format (no conversion)
impl<F: FftField + PrimeField> Into<Var<F>> for FieldChallenge<F> {
    fn into(self) -> Var<F> {
        self.inner.bits
    }
}

// a GLV challenge can be passed to itself
impl<Fr, Fp> Pass<FieldChallenge<Fr>> for FieldChallenge<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
}

impl<Fp, Fr> ToPublic<Fp, Fr> for FieldChallenge<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn to_public<Cp: Cs<Fp>>(self, cp: &mut Cp, cnst: &Constants<Fp>) -> Vec<Public<Fp>> {
        <Bits<Fp> as ToPublic<Fp, Fr>>::to_public::<Cp>(self.inner, cp, cnst)
    }
}

impl<Fp, Fr> FromPublic<Fp, Fr> for FieldChallenge<Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    type Error = ();

    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fr>>>(
        cs: &mut C,
        cnst: &Constants<Fr>,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        <Bits<Fr> as FromPublic<Fp, Fr>>::from_public::<C, I>(cs, cnst, inputs)
            .map(|inner| Self { inner })
    }
}
