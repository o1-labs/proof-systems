use ark_ff::{Field, PrimeField};
use oracle::poseidon::{
    ArithmeticSponge, ArithmeticSpongeParams, PlonkSpongeConstantsBasic as SC, Sponge,
};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};
use plonk_circuits::scalars::ProofEvaluations;

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> ScalarChallenge<Fr>;
    fn absorb_evaluations(&mut self, p: &[Fr], e: &ProofEvaluations<Vec<Fr>>);
}

impl<Fr: PrimeField> FrSponge<Fr> for DefaultFrSponge<Fr, SC> {
    fn new(params: ArithmeticSpongeParams<Fr>) -> DefaultFrSponge<Fr, SC> {
        DefaultFrSponge {
            sponge: ArithmeticSponge::new(params),
            last_squeezed: vec![],
        }
    }

    fn absorb(&mut self, x: &Fr) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&[*x]);
    }

    fn challenge(&mut self) -> ScalarChallenge<Fr> {
        ScalarChallenge(self.squeeze(oracle::sponge::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn absorb_evaluations(&mut self, p: &[Fr], e: &ProofEvaluations<Vec<Fr>>) {
        self.last_squeezed = vec![];
        self.sponge.absorb(p);

        let points = [&e.l, &e.r, &e.o, &e.z, &e.f, &e.sigma1, &e.sigma2, &e.t];

        for p in &points {
            self.sponge.absorb(p);
        }
    }
}
