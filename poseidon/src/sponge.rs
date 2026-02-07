extern crate alloc;

use crate::{
    constants::{PlonkSpongeConstantsKimchi, SpongeConstants},
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};
use alloc::{vec, vec::Vec};
use ark_ec::models::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

/// Abstracts a sponge operating on a base field `Fq` of the curve
/// `G`. The parameter `Fr` is modelling the scalar field of the
/// curve.
pub trait FqSponge<Fq: Field, G, Fr, const FULL_ROUNDS: usize> {
    /// Creates a new sponge.
    fn new(p: &'static ArithmeticSpongeParams<Fq, FULL_ROUNDS>) -> Self;

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

/// Number of 64-bit limbs used to represent a scalar challenge.
///
/// With 2 limbs, challenges are 128 bits. This is sufficient because:
///
/// **Endomorphism decomposition**: The challenge is converted to an effective
///  scalar k = a·λ + b where both a and b are derived from the 128-bit input.
///  Since λ is a cube root of unity in a ~255-bit scalar field, a 128-bit
///  challenge provides enough entropy for both components.
pub const CHALLENGE_LENGTH_IN_LIMBS: usize = 2;

const HIGH_ENTROPY_LIMBS: usize = 2;

/// A challenge which is used as a scalar on a group element in the verifier.
///
/// This wraps a field element that will be converted to an "effective" scalar
/// using the curve endomorphism for efficient scalar multiplication.
///
/// See [`ScalarChallenge::to_field`] for how the conversion works.
#[derive(Clone, Debug)]
pub struct ScalarChallenge<F>(F);

impl<F> ScalarChallenge<F> {
    /// Creates a [`ScalarChallenge`](Self) from a field element.
    ///
    /// # Deprecation
    ///
    /// This constructor will be deprecated in favor of [`Self::from_limbs`],
    /// which enforces the 128-bit constraint at construction.
    ///
    /// The field element is assumed to contain at most 128 bits of data
    /// (i.e., only the two lowest 64-bit limbs are set). This is the case
    /// when the value comes from [`FqSponge::challenge`].
    pub const fn new(challenge: F) -> Self {
        Self(challenge)
    }
}

/// Computes a primitive cube root of unity ξ in the field F.
///
/// For a prime field `F_p` where 3 divides p-1, this returns:
///
///   ξ = g^((p-1)/3)
///
/// where g is a generator of the multiplicative group `F_p*`.
///
/// # Properties
///
/// - ξ³ = g^(p-1) = 1 (by Fermat's Little Theorem)
/// - ξ ≠ 1 (since (p-1)/3 is not a multiple of p-1)
/// - The three cube roots of unity are: {1, ξ, ξ²}
///
/// # Usage
///
/// This is used in two contexts:
///
/// 1. **Base field (ξ)**: For the curve endomorphism φ(x,y) = (ξ·x, y)
/// 2. **Scalar field (λ)**: As the scalar such that `φ(P) = [λ]P`
///
/// Both fields (Fp and Fq for Pasta curves) have cube roots of unity,
/// and they correspond to each other via the endomorphism relationship.
///
/// # References
///
/// - Halo paper, Section 6.2: <https://eprint.iacr.org/2019/1021>
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
    /// Creates a [`ScalarChallenge`](Self) from exactly 128 bits (2 limbs).
    ///
    /// This is the preferred constructor as it enforces the 128-bit constraint
    /// required by [`Self::to_field`].
    ///
    /// # Panics
    ///
    /// Panics if the 128-bit value cannot be represented as a field element
    /// (unreachable for fields with modulus > 2^128).
    #[must_use]
    pub fn from_limbs(limbs: [u64; 2]) -> Self {
        Self(F::from_bigint(pack(&limbs)).expect("128 bits always fits in field"))
    }

    /// Get the inner value
    #[must_use]
    pub const fn inner(&self) -> F {
        self.0
    }

    /// Converts a scalar challenge to an "effective" scalar using endomorphism
    /// decomposition.
    ///
    /// # Background
    ///
    /// For curves with an endomorphism `φ(P) = [λ]P`, we can represent any scalar
    /// `k` as:
    ///
    ///   k = a·λ + b
    ///
    /// This allows efficient scalar multiplication because:
    ///
    ///   `[k]P = [a·λ + b]P = [a]·φ(P) + [b]·P`
    ///
    /// Since φ(P) = (ξ·x, y) is essentially free (one field multiplication),
    /// we reduce the scalar multiplication cost by processing two scalar
    /// multiplications of half the size instead of one full-size multiplication.
    ///
    /// # Algorithm
    ///
    /// Starting with a = b = 2, the challenge bits are processed in pairs
    /// (r_{2i}, r_{2i+1}) from MSB to LSB. For each pair:
    ///
    /// 1. Double both a and b
    /// 2. Add ±1 to either a or b based on the bit pair:
    ///
    /// | r_{2i} | r_{2i+1} | Action  |
    /// |--------|----------|---------|
    /// |   0    |    0     | b += -1 |
    /// |   1    |    0     | b += +1 |
    /// |   0    |    1     | a += -1 |
    /// |   1    |    1     | a += +1 |
    ///
    /// The result is: a·λ + b
    ///
    /// # Parameters
    ///
    /// - `length_in_bits`: Number of bits to process from the challenge
    /// - `endo_coeff`: The scalar λ such that `φ(P) = [λ]P`
    ///
    /// # Returns
    ///
    /// The effective scalar k = a·λ + b
    ///
    /// # References
    ///
    /// - Halo paper, Section 6.2: <https://eprint.iacr.org/2019/1021>
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

    /// Converts a scalar challenge to an effective scalar.
    ///
    /// This is a convenience wrapper around [`Self::to_field_with_length`]
    /// using the default challenge length (128 bits).
    ///
    /// See [`Self::to_field_with_length`] for details on the algorithm.
    pub fn to_field(&self, endo_coeff: &F) -> F {
        let length_in_bits = 64 * CHALLENGE_LENGTH_IN_LIMBS;
        self.to_field_with_length(length_in_bits, endo_coeff)
    }
}

#[derive(Clone)]
pub struct DefaultFqSponge<P: SWCurveConfig, SC: SpongeConstants, const FULL_ROUNDS: usize> {
    pub sponge: ArithmeticSponge<P::BaseField, SC, FULL_ROUNDS>,
    pub last_squeezed: Vec<u64>,
}

pub struct DefaultFrSponge<Fr: Field, SC: SpongeConstants, const FULL_ROUNDS: usize> {
    pub sponge: ArithmeticSponge<Fr, SC, FULL_ROUNDS>,
    pub last_squeezed: Vec<u64>,
}

impl<const FULL_ROUNDS: usize, Fr> From<&'static ArithmeticSpongeParams<Fr, FULL_ROUNDS>>
    for DefaultFrSponge<Fr, PlonkSpongeConstantsKimchi, FULL_ROUNDS>
where
    Fr: PrimeField,
{
    fn from(p: &'static ArithmeticSpongeParams<Fr, FULL_ROUNDS>) -> Self {
        Self {
            sponge: ArithmeticSponge::new(p),
            last_squeezed: vec![],
        }
    }
}

fn pack<B: BigInteger>(limbs_lsb: &[u64]) -> B {
    let mut res: B = 0u64.into();
    for &x in limbs_lsb.iter().rev() {
        res <<= 64;
        res.add_with_carry(&x.into());
    }
    res
}

impl<Fr: PrimeField, SC: SpongeConstants, const FULL_ROUNDS: usize>
    DefaultFrSponge<Fr, SC, FULL_ROUNDS>
{
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

impl<P: SWCurveConfig, SC: SpongeConstants, const FULL_ROUNDS: usize>
    DefaultFqSponge<P, SC, FULL_ROUNDS>
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

    /// Squeeze out a scalar field element from the sponge.
    ///
    /// # Panics
    ///
    /// Panics if the packed limbs cannot be converted to a valid scalar
    /// field element.
    pub fn squeeze(&mut self, num_limbs: usize) -> P::ScalarField {
        P::ScalarField::from_bigint(pack(&self.squeeze_limbs(num_limbs)))
            .expect("internal representation was not a valid field element")
    }
}

impl<P: SWCurveConfig, SC: SpongeConstants, const FULL_ROUNDS: usize>
    FqSponge<P::BaseField, Affine<P>, P::ScalarField, FULL_ROUNDS>
    for DefaultFqSponge<P, SC, FULL_ROUNDS>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn new(params: &'static ArithmeticSpongeParams<P::BaseField, FULL_ROUNDS>) -> Self {
        let sponge = ArithmeticSponge::new(params);
        Self {
            sponge,
            last_squeezed: vec![],
        }
    }

    fn absorb_g(&mut self, g: &[Affine<P>]) {
        self.last_squeezed = vec![];
        for pt in g {
            if pt.infinity {
                // absorb a fake point (0, 0)
                let zero = P::BaseField::zero();
                self.sponge.absorb(&[zero]);
                self.sponge.absorb(&[zero]);
            } else {
                self.sponge.absorb(&[pt.x]);
                self.sponge.absorb(&[pt.y]);
            }
        }
    }

    fn absorb_fq(&mut self, x: &[P::BaseField]) {
        self.last_squeezed = vec![];

        for fe in x {
            self.sponge.absorb(&[*fe]);
        }
    }

    fn absorb_fr(&mut self, x: &[P::ScalarField]) {
        self.last_squeezed = vec![];

        for elem in x {
            let bits = elem.into_bigint().to_bits_le();

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
        }
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
#[allow(non_local_definitions)]
pub mod caml {
    // The ocaml_gen::Struct derive macro requires items from parent scope
    // that cannot be enumerated explicitly.
    #[allow(clippy::wildcard_imports)]
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
