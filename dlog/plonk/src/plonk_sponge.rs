use crate::prover::ProofEvaluations;
use algebra::{
    Field, PrimeField,
};
use oracle::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> ScalarChallenge<Fr>;
    fn absorb_evaluations(&mut self, x_hat_beta1: &[Fr], e: &ProofEvaluations<Fr>);
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

    fn challenge(&mut self) -> ScalarChallenge<Fr> {
        ScalarChallenge(self.squeeze(oracle::sponge::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn absorb_evaluations(&mut self, x_hat: &[Fr], e: &ProofEvaluations<Fr>) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&self.params, x_hat);

        let points = [
            &e._x,
        ];

        for p in &points {
            self.sponge.absorb(&self.params, p);
        }
    }
}
