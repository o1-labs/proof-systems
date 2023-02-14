use crate::constants::SpongeConstants;
use crate::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::{BigInteger, Field, FpParameters, One, PrimeField, Zero};

#[cfg(feature = "debug_sponge")]
use o1_utils::FieldHelpers;

pub use crate::FqSponge;

pub const CHALLENGE_LENGTH_IN_LIMBS: usize = 2;

const HIGH_ENTROPY_LIMBS: usize = 2;

// TODO: move to a different file / module
/// A challenge which is used as a scalar on a group element in the verifier
#[derive(Clone, Debug)]
pub struct ScalarChallenge<F>(pub F);

pub fn endo_coefficient<F: PrimeField>() -> F {
    let p_minus_1_over_3 = (F::zero() - F::one()) / F::from(3u64);

    let t = F::multiplicative_generator();

    t.pow(p_minus_1_over_3.into_repr().as_ref())
}

fn get_bit(limbs_lsb: &[u64], i: u64) -> u64 {
    let limb = i / 64;
    let j = i % 64;
    (limbs_lsb[limb as usize] >> j) & 1
}

impl<F: PrimeField> ScalarChallenge<F> {
    pub fn to_field_with_length(&self, length_in_bits: usize, endo_coeff: &F) -> F {
        let rep = self.0.into_repr();
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
pub struct DefaultFqSponge<P: SWModelParameters, SC: SpongeConstants> {
    pub sponge: ArithmeticSponge<P::BaseField, SC>,
    pub last_squeezed: Vec<u64>,
}

pub struct DefaultFrSponge<Fr: Field, SC: SpongeConstants> {
    pub sponge: ArithmeticSponge<Fr, SC>,
    pub last_squeezed: Vec<u64>,
}

fn pack<B: BigInteger>(limbs_lsb: &[u64]) -> B {
    let mut res: B = 0.into();
    for &x in limbs_lsb.iter().rev() {
        res.muln(64);
        res.add_nocarry(&x.into());
    }
    res
}

impl<Fr: PrimeField, SC: SpongeConstants> DefaultFrSponge<Fr, SC> {
    pub fn squeeze(&mut self, num_limbs: usize) -> Fr {
        if self.last_squeezed.len() >= num_limbs {
            let last_squeezed = self.last_squeezed.clone();
            let (limbs, remaining) = last_squeezed.split_at(num_limbs);
            self.last_squeezed = remaining.to_vec();
            Fr::from_repr(pack::<Fr::BigInt>(limbs))
                .expect("internal representation was not a valid field element")
        } else {
            let x = self.sponge.squeeze().into_repr();
            self.last_squeezed
                .extend(&x.as_ref()[0..HIGH_ENTROPY_LIMBS]);
            self.squeeze(num_limbs)
        }
    }
}

impl<P: SWModelParameters, SC: SpongeConstants> DefaultFqSponge<P, SC>
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
            let x = self.sponge.squeeze().into_repr();
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
        P::ScalarField::from_repr(pack(&self.squeeze_limbs(num_limbs)))
            .expect("internal representation was not a valid field element")
    }
}

// Debugging macros -- these only insert code when non-release build and
// "debug_sponge" feature is enabled.
macro_rules! debug_sponge {
    ($name:expr, $sponge:expr) => {
        #[cfg(feature = "debug_sponge")]
        {
            // No input
            debug_sponge_print_state!($name, $sponge);
        }
    };
    ($name:expr, $input:expr, $sponge:expr) => {
        #[cfg(feature = "debug_sponge")]
        {
            // Field input
            debug_sponge_print_state!($name, $sponge);

            println!(
                "debug_sponge: id{} {} input {}",
                $sponge.id,
                $name,
                $input.to_hex()
            );
        }
    };
}
#[cfg(feature = "debug_sponge")]
macro_rules! debug_sponge_print_state {
    ($name:expr, $sponge:expr) => {
        println!(
            "debug_sponge: id{} {} state {:?} {}",
            $sponge.id,
            $name,
            $sponge.sponge_state,
            $sponge
                .state
                .iter()
                .map(|f| { f.to_hex() })
                .collect::<Vec<String>>()
                .join(" "),
        );
    };
}

impl<P: SWModelParameters, SC: SpongeConstants>
    FqSponge<P::BaseField, GroupAffine<P>, P::ScalarField> for DefaultFqSponge<P, SC>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn new(params: &'static ArithmeticSpongeParams<P::BaseField>) -> DefaultFqSponge<P, SC> {
        let sponge = ArithmeticSponge::new(params);
        debug_sponge!("new", sponge);
        DefaultFqSponge {
            sponge,
            last_squeezed: vec![],
        }
    }

    fn absorb_g(&mut self, g: &[GroupAffine<P>]) {
        self.last_squeezed = vec![];
        for g in g.iter() {
            if g.infinity {
                // absorb a fake point (0, 0)
                let zero = P::BaseField::zero();
                debug_sponge!("absorb", zero, self.sponge);
                self.sponge.absorb(&[zero]);
                debug_sponge!("absorb", zero, self.sponge);
                self.sponge.absorb(&[zero]);
            } else {
                debug_sponge!("absorb", g.x, self.sponge);
                self.sponge.absorb(&[g.x]);
                debug_sponge!("absorb", g.y, self.sponge);
                self.sponge.absorb(&[g.y]);
            }
        }
    }

    fn absorb_fq(&mut self, x: &[P::BaseField]) {
        self.last_squeezed = vec![];

        for fe in x {
            debug_sponge!("absorb", fe, self.sponge);
            self.sponge.absorb(&[*fe])
        }
    }

    fn absorb_fr(&mut self, x: &[P::ScalarField]) {
        self.last_squeezed = vec![];

        x.iter().for_each(|x| {
            let bits = x.into_repr().to_bits_le();

            // absorb
            if <P::ScalarField as PrimeField>::Params::MODULUS
                < <P::BaseField as PrimeField>::Params::MODULUS.into()
            {
                let fe = P::BaseField::from_repr(
                    <P::BaseField as PrimeField>::BigInt::from_bits_le(&bits),
                )
                .expect("padding code has a bug");
                debug_sponge!("absorb", fe, self.sponge);
                self.sponge.absorb(&[fe]);
            } else {
                let low_bit = if bits[0] {
                    P::BaseField::one()
                } else {
                    P::BaseField::zero()
                };

                let high_bits = P::BaseField::from_repr(
                    <P::BaseField as PrimeField>::BigInt::from_bits_le(&bits[1..bits.len()]),
                )
                .expect("padding code has a bug");

                debug_sponge!("absorb", high_bits, self.sponge);
                self.sponge.absorb(&[high_bits]);
                debug_sponge!("absorb", low_bit, self.sponge);
                self.sponge.absorb(&[low_bit]);
            }
        });
    }

    fn digest(mut self) -> P::ScalarField {
        debug_sponge!("squeeze", self.sponge);
        let x: <P::BaseField as PrimeField>::BigInt = self.squeeze_field().into_repr();
        // Returns zero for values that are too large.
        // This means that there is a bias for the value zero (in one of the curve).
        // An attacker could try to target that seed, in order to predict the challenges u and v produced by the Fr-Sponge.
        // This would allow the attacker to mess with the result of the aggregated evaluation proof.
        // Previously the attacker's odds were 1/q, now it's (q-p)/q.
        // Since log2(q-p) ~ 86 and log2(q) ~ 254 the odds of a successful attack are negligible.
        P::ScalarField::from_repr(x.into()).unwrap_or_else(P::ScalarField::zero)
    }

    fn digest_fq(mut self) -> P::BaseField {
        debug_sponge!("squeeze", self.sponge);
        self.squeeze_field()
    }

    fn challenge(&mut self) -> P::ScalarField {
        debug_sponge!("squeeze", self.sponge);
        self.squeeze(CHALLENGE_LENGTH_IN_LIMBS)
    }

    fn challenge_fq(&mut self) -> P::BaseField {
        debug_sponge!("squeeze", self.sponge);
        self.squeeze_field()
    }
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;

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
