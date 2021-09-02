use crate::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge, SpongeConstants};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::{BigInteger, Field, FpParameters, One, PrimeField, Zero};

pub use crate::FqSponge;

pub const CHALLENGE_LENGTH_IN_LIMBS: usize = 2;

const HIGH_ENTROPY_LIMBS: usize = 2;

// TODO: move to a different file / module
/// A challenge which is used as a scalar on a group element in the verifier
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::IntoValue, ocaml::FromValue))]
pub struct ScalarChallenge<F>(pub F);

pub fn endo_coefficient<F: PrimeField>() -> F {
    let p_minus_1_over_3 = ((F::zero() - &F::one()) / &(3 as u64).into()).into_repr();

    let t = F::multiplicative_generator();

    t.pow(p_minus_1_over_3.as_ref())
}

fn get_bit(limbs_lsb: &[u64], i: u64) -> u64 {
    let limb = i / 64;
    let j = i % 64;
    (limbs_lsb[limb as usize] >> j) & 1
}

impl<F: PrimeField> ScalarChallenge<F> {
    pub fn to_field(&self, endo_coeff: &F) -> F {
        let length_in_bits: u64 = (64 * CHALLENGE_LENGTH_IN_LIMBS) as u64;
        let rep = self.0.into_repr();
        let r = rep.as_ref();

        let mut a: F = (2 as u64).into();
        let mut b: F = (2 as u64).into();

        let one = F::one();
        let neg_one = -one;

        for i in (0..(length_in_bits / 2)).rev() {
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

        a * endo_coeff + &b
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
            Fr::from_repr(pack::<Fr::BigInt>(&limbs))
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

impl<P: SWModelParameters, SC: SpongeConstants>
    FqSponge<P::BaseField, GroupAffine<P>, P::ScalarField> for DefaultFqSponge<P, SC>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn new(params: ArithmeticSpongeParams<P::BaseField>) -> DefaultFqSponge<P, SC> {
        DefaultFqSponge {
            sponge: ArithmeticSponge::new(params),
            last_squeezed: vec![],
        }
    }

    fn absorb_g(&mut self, g: &[GroupAffine<P>]) {
        self.last_squeezed = vec![];
        for g in g.iter() {
            if g.infinity {
                // absorb a fake point (0, 0)
                let zero = P::BaseField::zero();
                self.sponge.absorb(&[zero, zero]);
            } else {
                self.sponge.absorb(&[g.x]);
                self.sponge.absorb(&[g.y]);
            }
        }
    }

    fn absorb_fr(&mut self, x: &[P::ScalarField]) {
        self.last_squeezed = vec![];
        let total_length = P::ScalarField::size_in_bits();

        x.iter().for_each(|x| {
            // padding (since unpadded_bits is a BigInt, it can be larger than the total_length)
            let unpadded_bits = x.into_repr().to_bits_be();
            let padding = total_length.saturating_sub(unpadded_bits.len());
            let mut bits = vec![false; padding];
            bits.extend_from_slice(&unpadded_bits);

            // absorb
            if <P::ScalarField as PrimeField>::Params::MODULUS
                < <P::BaseField as PrimeField>::Params::MODULUS.into()
            {
                self.sponge.absorb(&[P::BaseField::from_repr(
                    <P::BaseField as PrimeField>::BigInt::from_bits_be(&bits),
                )
                .expect("padding code has a bug")]);
            } else {
                let low_bits = P::BaseField::from_repr(
                    <P::BaseField as PrimeField>::BigInt::from_bits_be(&bits[1..]),
                )
                .expect("padding code has a bug");

                let high_bit = if bits[0] {
                    P::BaseField::one()
                } else {
                    P::BaseField::zero()
                };

                self.sponge.absorb(&[low_bits]);
                self.sponge.absorb(&[high_bit]);
            }
        });
    }

    fn digest(mut self) -> P::ScalarField {
        let x: <P::BaseField as PrimeField>::BigInt = self.squeeze_field().into_repr();
        P::ScalarField::from_repr(x.into()).expect("the sponge code has a bug")
    }

    fn challenge(&mut self) -> P::ScalarField {
        self.squeeze(CHALLENGE_LENGTH_IN_LIMBS)
    }

    fn challenge_fq(&mut self) -> P::BaseField {
        self.squeeze_field()
    }
}
