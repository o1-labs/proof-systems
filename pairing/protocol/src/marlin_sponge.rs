use crate::prover::ProofEvaluations;
use algebra::{
    Field, PairingEngine, PrimeField,
};

use oracle::{marlin_sponge::{DefaultFrSponge, FqSponge}, poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge}};

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> Fr;
    fn absorb_evaluations(&mut self, x_hat: &Fr, e: &ProofEvaluations<Fr>);
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
        self.sponge.absorb(&self.params, &[*x]);
    }

    fn challenge(&mut self) -> Fr {
        self.squeeze(oracle::marlin_sponge::CHALLENGE_LENGTH_IN_LIMBS)
    }

    fn absorb_evaluations(&mut self, x_hat: &Fr, e: &ProofEvaluations<Fr>) {
        self.last_squeezed = vec![];

        let points = [
            *x_hat,
            e.w,
            e.za,
            e.zb,
            e.h1,
            e.h2,
            e.h3,
            e.row[0],
            e.row[1],
            e.row[2],
            e.col[0],
            e.col[1],
            e.col[2],
            e.val[0],
            e.val[1],
            e.val[2],
            e.rc[0],
            e.rc[1],
            e.rc[2],
            e.g1,
            e.g2,
            e.g3,
        ];

        for p in &points {
            self.sponge.absorb(&self.params, &[*p]);
        }
    }
}
