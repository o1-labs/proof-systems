use ark_ff::{FftField, PrimeField};

use circuit_construction::{Constants, Cs, Var};

use super::Bits;

use crate::context::{FromPublic, Pass, Public, ToPublic};
use crate::transcript::{Challenge, VarSponge};

/// A collection of CHALLENGE_LEN bits representing a GLV decomposition
pub struct GLVChallenge<F: FftField + PrimeField> {
    inner: Bits<F>,
}

// a GLV challenge can be passed to itself
impl<Fr, Fp> Pass<GLVChallenge<Fr>> for GLVChallenge<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
}

impl<F: FftField + PrimeField> Challenge<F> for GLVChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        Self {
            inner: Bits::generate(cs, sponge),
        }
    }
}

impl<Fp, Fr> ToPublic<Fp, Fr> for GLVChallenge<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn to_public<Cp: Cs<Fp>>(self, cp: &mut Cp, cnst: &Constants<Fp>) -> Vec<Public<Fp>> {
        <Bits<Fp> as ToPublic<Fp, Fr>>::to_public::<Cp>(self.inner, cp, cnst)
    }
}

impl<Fp, Fr> FromPublic<Fp, Fr> for GLVChallenge<Fr>
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

impl<F: FftField + PrimeField> GLVChallenge<F> {
    pub fn to_field<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        unimplemented!()
    }
}
