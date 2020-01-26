use crate::prover::ProofEvaluations;
use algebra::{
    curves::{short_weierstrass_jacobian::GroupAffine, SWModelParameters},
    BigInteger, Field, FpParameters, PairingEngine, PrimeField,
};
use oracle::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge};
use oracle::FqSponge;

const DIGEST_LENGTH: usize = 256;
const CHALLENGE_LENGTH: usize = 128;

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> Fr;
    fn absorb_evaluations(&mut self, x_hat_beta1: &Fr, e: &ProofEvaluations<Fr>);
}

pub trait SpongePairingEngine: PairingEngine {
    type FqSponge: FqSponge<Self::Fq, Self::G1Affine, Self::Fr>;
    type FrSponge: FrSponge<Self::Fr>;
}

pub struct DefaultFqSponge<P: SWModelParameters> {
    params: ArithmeticSpongeParams<P::BaseField>,
    sponge: ArithmeticSponge<P::BaseField>,
}

pub struct DefaultFrSponge<Fr: Field> {
    params: ArithmeticSpongeParams<Fr>,
    sponge: ArithmeticSponge<Fr>,
}

impl<Fr: PrimeField> FrSponge<Fr> for DefaultFrSponge<Fr> {
    fn new(params: ArithmeticSpongeParams<Fr>) -> DefaultFrSponge<Fr> {
        DefaultFrSponge {
            params,
            sponge: ArithmeticSponge::new(),
        }
    }

    fn absorb(&mut self, x: &Fr) {
        self.sponge.absorb(&self.params, &[*x]);
    }

    fn challenge(&mut self) -> Fr {
        let x = &self.sponge.squeeze(&self.params).into_repr().to_bits();

        Fr::from_repr(Fr::BigInt::from_bits(&x[..CHALLENGE_LENGTH]))
    }

    fn absorb_evaluations(&mut self, x_hat_beta1: &Fr, e: &ProofEvaluations<Fr>) {
        // beta1 evaluations
        self.sponge.absorb(&self.params, &[*x_hat_beta1]);
        for x in &[e.w, e.g1, e.h1, e.za, e.zb] {
            self.sponge.absorb(&self.params, &[*x]);
        }

        // beta2 evaluations
        for x in &[e.g2, e.h2] {
            self.sponge.absorb(&self.params, &[*x]);
        }

        // beta3 evaluations
        for x in &[e.g3, e.h3] {
            self.sponge.absorb(&self.params, &[*x]);
        }
        for t in &[e.row, e.col, e.val] {
            for x in t {
                self.sponge.absorb(&self.params, &[*x]);
            }
        }
    }
}

impl<P: SWModelParameters> FqSponge<P::BaseField, GroupAffine<P>, P::ScalarField>
    for DefaultFqSponge<P>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn new(params: ArithmeticSpongeParams<P::BaseField>) -> DefaultFqSponge<P> {
        DefaultFqSponge {
            params,
            sponge: ArithmeticSponge::new(),
        }
    }

    fn absorb_g(&mut self, g: &GroupAffine<P>) {
        if g.infinity {
            panic!("marlin sponge got zero curve point");
        } else {
            self.sponge.absorb(&self.params, &[g.x]);
            self.sponge.absorb(&self.params, &[g.y]);
        }
    }

    fn absorb_fr(&mut self, x: &P::ScalarField) {
        let bits: Vec<bool> = x.into_repr().to_bits();

        if <P::ScalarField as PrimeField>::Params::MODULUS
            < <P::BaseField as PrimeField>::Params::MODULUS.into()
        {
            self.sponge.absorb(
                &self.params,
                &[P::BaseField::from_repr(<P::BaseField as PrimeField>::BigInt::from_bits(&bits))],
            );
        } else {
            let low_bits = &bits[..(bits.len() - 1)];
            let high_bit = if bits[bits.len() - 1] {
                P::BaseField::one()
            } else {
                P::BaseField::zero()
            };
            self.sponge.absorb(
                &self.params,
                &[P::BaseField::from_repr(<P::BaseField as PrimeField>::BigInt::from_bits(
                    &low_bits,
                ))],
            );
            self.sponge.absorb(&self.params, &[high_bit]);
        }
    }

    fn digest(mut self) -> P::ScalarField {
        let x = self.sponge.squeeze(&self.params).into_repr();
        let x: &[bool] = &x.to_bits()[..DIGEST_LENGTH];
        let x = <P::ScalarField as PrimeField>::BigInt::from_bits(x);
        P::ScalarField::from_repr(x)
    }

    fn challenge(&mut self) -> P::ScalarField {
        let x = self.sponge.squeeze(&self.params).into_repr();

        P::ScalarField::from_repr(<P::ScalarField as PrimeField>::BigInt::from_bits(
            &x.to_bits()[..CHALLENGE_LENGTH],
        ))
    }
}
