use circuit_construction::{Cs, Var, Constants};

use crate::context::{FromPublic, Public, ToPublic};
use crate::transcript::{Challenge, VarSponge};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

const CHALLENGE_LEN: usize = 128;

// a challenge in GLV decomposed form
mod glv;

// a challenge in the form of a field element (of bounded size)
mod field;

pub use field::FieldChallenge;
pub use glv::GLVChallenge;

// all challenges take the form of 128 random bits
// (but the interpretation may be different)
struct Bits<F: FftField + PrimeField> {
    bits: Var<F>,
}

impl<Fp, Fr> ToPublic<Fp, Fr> for Bits<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    // it always fits
    fn to_public<Cp: Cs<Fp>>(self, _: &mut Cp, _: &Constants<Fp>) -> Vec<Public<Fp>> {
        assert!(Fp::Params::MODULUS.num_bits() as usize > CHALLENGE_LEN);
        assert!(Fr::Params::MODULUS.num_bits() as usize > CHALLENGE_LEN);
        vec![Public {
            size: Some(CHALLENGE_LEN),
            bits: self.bits,
        }]
    }
}

impl<Fp, Fr> FromPublic<Fp, Fr> for Bits<Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    type Error = ();

    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fr>>>(
        cs: &mut C,
        _cnst: &Constants<Fr>,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        assert!(Fp::Params::MODULUS.num_bits() as usize > CHALLENGE_LEN);
        assert!(Fr::Params::MODULUS.num_bits() as usize > CHALLENGE_LEN);

        let bits = inputs.next().unwrap();
        assert_eq!(bits.size, Some(CHALLENGE_LEN));
        Ok(Bits { bits: bits.bits })
    }
}

impl<F: FftField + PrimeField> Challenge<F> for Bits<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        // squeeze 128-bits
        unimplemented!()
    }
}
