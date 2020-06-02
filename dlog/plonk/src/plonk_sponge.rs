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
    fn absorb_evaluations(&mut self, x_hat_beta1: &[Fr], e: &ProofEvaluations<Vec<Fr>>);
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

    fn absorb_evaluations(&mut self, x_hat: &[Fr], e: &ProofEvaluations<Vec<Fr>>) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&self.params, x_hat);

        let points = [
            &e.l,
            &e.t,
            &e.o,
            &e.z,
            &e.t,

            &e.ql,
            &e.qr,
            &e.qo,
            &e.qm,
            &e.qc,

            &e.sigma[0],
            &e.sigma[1],
            &e.sigma[2],
        ];

        for p in &points {
            self.sponge.absorb(&self.params, p);
        }
    }
}
