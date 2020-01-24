use crate::prover::ProofEvaluations;
use algebra::{
    Field, PairingEngine, PrimeField,
};

use oracle::{marlin_sponge::{DefaultFrSponge, FqSponge}, poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge}};

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

impl<Fr: PrimeField> FrSponge<Fr> for DefaultFrSponge<Fr> {
    fn new(params: ArithmeticSpongeParams<Fr>) -> DefaultFrSponge<Fr> {
        DefaultFrSponge {
            params,
            sponge: ArithmeticSponge::new(),
            last_squeezed: vec![],
        }
    }

    fn absorb(&mut self, x: &Fr) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&self.params, x);
    }

    fn challenge(&mut self) -> Fr {
        self.squeeze(oracle::marlin_sponge::CHALLENGE_LENGTH_IN_LIMBS)
    }

    fn absorb_evaluations(&mut self, x_hat_beta1: &Fr, e: &ProofEvaluations<Fr>) {
        self.last_squeezed = vec![];
        // beta1 evaluations
        self.sponge.absorb(&self.params, x_hat_beta1);
        for x in &[e.w, e.g1, e.h1, e.za, e.zb] {
            self.sponge.absorb(&self.params, x);
        }

        // beta2 evaluations
        for x in &[e.g2, e.h2] {
            self.sponge.absorb(&self.params, x);
        }

        // beta3 evaluations
        for x in &[e.g3, e.h3] {
            self.sponge.absorb(&self.params, x);
        }
        for t in &[e.row, e.col, e.val, e.rc] {
            for x in t {
                self.sponge.absorb(&self.params, x);
            }
        }
    }
}
