use circuit_construction::{Cs, Var};

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

impl<Fp: FftField + PrimeField> ToPublic<Fp> for Bits<Fp> {
    fn to_public(&self) -> Vec<Public<Fp>> {
        vec![Public {
            size: Some(CHALLENGE_LEN),
            bits: self.bits,
        }]
    }
}

impl<Fq: FftField + PrimeField, Fr: FftField + PrimeField> FromPublic<Fq, Fr> for Bits<Fr> {
    type Error = ();

    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fq>>>(
        cs: &mut C,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        assert!(Fq::Params::MODULUS.num_bits() as usize > CHALLENGE_LEN);
        assert!(Fr::Params::MODULUS.num_bits() as usize > CHALLENGE_LEN);

        // bit decompose Fq element
        let bits = inputs.next().unwrap();
        let bits = bits.bits.value.map(|v| v.into_repr().to_bits_le());

        // converts a slice of bits (minimal representative) to a field element
        fn from_bits<F: FftField + PrimeField>(bits: &[bool]) -> F {
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(bits)).unwrap()
        }

        // pack into Fr
        Ok(Bits {
            bits: cs.var(|| from_bits(&bits.unwrap()[..CHALLENGE_LEN])),
        })
    }
}

impl<F: FftField + PrimeField> Challenge<F> for Bits<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        // squeeze 128-bits
        unimplemented!()
    }
}
