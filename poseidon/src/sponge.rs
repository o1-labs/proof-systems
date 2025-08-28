extern crate alloc;
use crate::{
    constants::SpongeConstants,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};
use alloc::{vec, vec::Vec};
use ark_ec::models::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

/// Abstracts a sponge operating on a base field `Fq` of the curve
/// `G`. The parameter `Fr` is modelling the scalar field of the
/// curve.
pub trait FqSponge<Fq: Field, G, Fr> {
    /// Creates a new sponge.
    fn new(p: &'static ArithmeticSpongeParams<Fq>) -> Self;

    /// Absorbs a base field element. This operation is the most
    /// straightforward and calls the underlying sponge directly.
    fn absorb_fq(&mut self, x: &[Fq]);

    /// Absorbs a base field point, that is a pair of `Fq` elements.
    /// In the case of the point to infinity, the values `(0, 0)` are absorbed.
    fn absorb_g(&mut self, g: &[G]);

    /// Absorbs an element of the scalar field `Fr` --- it is done
    /// by converting the element to the base field first.
    fn absorb_fr(&mut self, x: &[Fr]);

    /// Squeeze out a base field challenge. This operation is the most
    /// direct and calls the underlying sponge.
    fn challenge_fq(&mut self) -> Fq;

    /// Squeeze out a challenge in the scalar field. Implemented by
    /// squeezing out base points and then converting them to a scalar
    /// field element using binary representation.
    fn challenge(&mut self) -> Fr;

    /// Returns a base field digest by squeezing the underlying sponge directly.
    fn digest_fq(self) -> Fq;

    /// Returns a scalar field digest using the binary representation technique.
    fn digest(self) -> Fr;
}

pub const CHALLENGE_LENGTH_IN_LIMBS: usize = 2;

const HIGH_ENTROPY_LIMBS: usize = 2;

// TODO: move to a different file / module
/// A challenge which is used as a scalar on a group element in the verifier
#[derive(Clone, Debug)]
pub struct ScalarChallenge<F>(pub F);

pub fn endo_coefficient<F: PrimeField>() -> F {
    let p_minus_1_over_3 = (F::zero() - F::one()) / F::from(3u64);

    F::GENERATOR.pow(p_minus_1_over_3.into_bigint().as_ref())
}

fn get_bit(limbs_lsb: &[u64], i: u64) -> u64 {
    let limb = i / 64;
    let j = i % 64;
    (limbs_lsb[limb as usize] >> j) & 1
}

impl<F: PrimeField> ScalarChallenge<F> {
    pub fn to_field_with_length(&self, length_in_bits: usize, endo_coeff: &F) -> F {
        let rep = self.0.into_bigint();
        let r = rep.as_ref();

        let mut a: F = 2_u64.into();
        let mut b: F = 2_u64.into();

        let one = F::one();
        let neg_one = -one;

        for i in (0..(length_in_bits as u64 / 2)).rev() {
            a.double_in_place();
            b.double_in_place();

            let r_2i = get_bit(r, 2 * i);
            let s = if r_2i == 0 { &neg_one } else { &one };

            if get_bit(r, 2 * i + 1) == 0 {
                b += s;
            } else {
                a += s;
            }
        }

        a * endo_coeff + b
    }

    pub fn to_field(&self, endo_coeff: &F) -> F {
        let length_in_bits = 64 * CHALLENGE_LENGTH_IN_LIMBS;
        self.to_field_with_length(length_in_bits, endo_coeff)
    }
}

#[derive(Clone)]
pub struct DefaultFqSponge<P: SWCurveConfig, SC: SpongeConstants> {
    pub sponge: ArithmeticSponge<P::BaseField, SC>,
    pub last_squeezed: Vec<u64>,
}

pub struct DefaultFrSponge<Fr: Field, SC: SpongeConstants> {
    pub sponge: ArithmeticSponge<Fr, SC>,
    pub last_squeezed: Vec<u64>,
}

fn pack<B: BigInteger>(limbs_lsb: &[u64]) -> B {
    let mut res: B = 0u64.into();
    for &x in limbs_lsb.iter().rev() {
        res <<= 64;
        res.add_with_carry(&x.into());
    }
    res
}

impl<Fr: PrimeField, SC: SpongeConstants> DefaultFrSponge<Fr, SC> {
    pub fn squeeze(&mut self, num_limbs: usize) -> Fr {
        if self.last_squeezed.len() >= num_limbs {
            let last_squeezed = self.last_squeezed.clone();
            let (limbs, remaining) = last_squeezed.split_at(num_limbs);
            self.last_squeezed = remaining.to_vec();
            Fr::from(pack::<Fr::BigInt>(limbs))
        } else {
            let x = self.sponge.squeeze().into_bigint();
            self.last_squeezed
                .extend(&x.as_ref()[0..HIGH_ENTROPY_LIMBS]);
            self.squeeze(num_limbs)
        }
    }
}

impl<P: SWCurveConfig, SC: SpongeConstants> DefaultFqSponge<P, SC>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    pub fn squeeze_limbs(&mut self, num_limbs: usize) -> Vec<u64> {
        if self.last_squeezed.len() >= num_limbs {
            let last_squeezed = self.last_squeezed.clone();
            let (limbs, remaining) = last_squeezed.split_at(num_limbs);
            self.last_squeezed = remaining.to_vec();
            limbs.to_vec()
        } else {
            let x = self.sponge.squeeze().into_bigint();
            self.last_squeezed
                .extend(&x.as_ref()[0..HIGH_ENTROPY_LIMBS]);
            self.squeeze_limbs(num_limbs)
        }
    }

    pub fn squeeze_field(&mut self) -> P::BaseField {
        self.last_squeezed = vec![];
        self.sponge.squeeze()
    }

    pub fn squeeze(&mut self, num_limbs: usize) -> P::ScalarField {
        P::ScalarField::from_bigint(pack(&self.squeeze_limbs(num_limbs)))
            .expect("internal representation was not a valid field element")
    }
}

impl<P: SWCurveConfig, SC: SpongeConstants> FqSponge<P::BaseField, Affine<P>, P::ScalarField>
    for DefaultFqSponge<P, SC>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn new(params: &'static ArithmeticSpongeParams<P::BaseField>) -> DefaultFqSponge<P, SC> {
        let sponge = ArithmeticSponge::new(params);
        DefaultFqSponge {
            sponge,
            last_squeezed: vec![],
        }
    }

    fn absorb_g(&mut self, g: &[Affine<P>]) {
        self.last_squeezed = vec![];
        for g in g.iter() {
            if g.infinity {
                // absorb a fake point (0, 0)
                let zero = P::BaseField::zero();
                self.sponge.absorb(&[zero]);
                self.sponge.absorb(&[zero]);
            } else {
                self.sponge.absorb(&[g.x]);
                self.sponge.absorb(&[g.y]);
            }
        }
    }

    fn absorb_fq(&mut self, x: &[P::BaseField]) {
        self.last_squeezed = vec![];

        for fe in x {
            self.sponge.absorb(&[*fe])
        }
    }

    fn absorb_fr(&mut self, x: &[P::ScalarField]) {
        self.last_squeezed = vec![];

        x.iter().for_each(|x| {
            let bits = x.into_bigint().to_bits_le();

            // absorb
            if <P::ScalarField as PrimeField>::MODULUS
                < <P::BaseField as PrimeField>::MODULUS.into()
            {
                let fe = P::BaseField::from_bigint(
                    <P::BaseField as PrimeField>::BigInt::from_bits_le(&bits),
                )
                .expect("padding code has a bug");
                self.sponge.absorb(&[fe]);
            } else {
                let low_bit = if bits[0] {
                    P::BaseField::one()
                } else {
                    P::BaseField::zero()
                };

                let high_bits = P::BaseField::from_bigint(
                    <P::BaseField as PrimeField>::BigInt::from_bits_le(&bits[1..bits.len()]),
                )
                .expect("padding code has a bug");

                self.sponge.absorb(&[high_bits]);
                self.sponge.absorb(&[low_bit]);
            }
        });
    }

    fn digest(mut self) -> P::ScalarField {
        let x: <P::BaseField as PrimeField>::BigInt = self.squeeze_field().into_bigint();
        // Returns zero for values that are too large.
        // This means that there is a bias for the value zero (in one of the curve).
        // An attacker could try to target that seed, in order to predict the challenges u and v produced by the Fr-Sponge.
        // This would allow the attacker to mess with the result of the aggregated evaluation proof.
        // Previously the attacker's odds were 1/q, now it's (q-p)/q.
        // Since log2(q-p) ~ 86 and log2(q) ~ 254 the odds of a successful attack are negligible.
        P::ScalarField::from_bigint(x.into()).unwrap_or_else(P::ScalarField::zero)
    }

    fn digest_fq(mut self) -> P::BaseField {
        self.squeeze_field()
    }

    fn challenge(&mut self) -> P::ScalarField {
        self.squeeze(CHALLENGE_LENGTH_IN_LIMBS)
    }

    fn challenge_fq(&mut self) -> P::BaseField {
        self.squeeze_field()
    }
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;

    extern crate alloc;
    use alloc::{
        format,
        string::{String, ToString},
    };

    //
    // ScalarChallenge<F> <-> CamlScalarChallenge<CamlF>
    //

    #[derive(Debug, Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlScalarChallenge<CamlF>(pub CamlF);

    impl<F, CamlF> From<ScalarChallenge<F>> for CamlScalarChallenge<CamlF>
    where
        CamlF: From<F>,
    {
        fn from(sc: ScalarChallenge<F>) -> Self {
            Self(sc.0.into())
        }
    }

    impl<F, CamlF> From<CamlScalarChallenge<CamlF>> for ScalarChallenge<F>
    where
        CamlF: Into<F>,
    {
        fn from(caml_sc: CamlScalarChallenge<CamlF>) -> Self {
            Self(caml_sc.0.into())
        }
    }
}
