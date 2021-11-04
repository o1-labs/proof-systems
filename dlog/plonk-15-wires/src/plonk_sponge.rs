use ark_ff::{Field, PrimeField};
use oracle::poseidon::{
    ArithmeticSponge, ArithmeticSpongeParams, PlonkSpongeConstants15W as SC, Sponge,
};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};
use plonk_15_wires_circuits::nolookup::scalars::ProofEvaluations;

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
        // TODO: why involve sponge_5_wires here?
        ScalarChallenge(self.squeeze(oracle::sponge::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn absorb_evaluations(&mut self, p: &[Fr], e: &ProofEvaluations<Vec<Fr>>) {
        self.last_squeezed = vec![];
        self.sponge.absorb(p);

        let points = [
            &e.z,
            &e.generic_selector,
            &e.poseidon_selector,
            &e.w[0],
            &e.w[1],
            &e.w[2],
            &e.w[3],
            &e.w[4],
            &e.w[5],
            &e.w[6],
            &e.w[7],
            &e.w[8],
            &e.w[9],
            &e.w[10],
            &e.w[11],
            &e.w[12],
            &e.w[13],
            &e.w[14],
            &e.s[0],
            &e.s[1],
            &e.s[2],
            &e.s[3],
            &e.s[4],
            &e.s[5],
        ];

        for p in &points {
            self.sponge.absorb(p);
        }
    }
}
