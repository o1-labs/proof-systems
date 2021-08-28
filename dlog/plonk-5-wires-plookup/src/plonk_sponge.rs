use ark_ff::{Field, PrimeField};
use oracle::poseidon::{ArithmeticSponge, PlonkSpongeConstants5W as SC};
use oracle::poseidon::{ArithmeticSpongeParams, Sponge};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};
use plonk_5_wires_plookup_circuits::scalars::ProofEvaluations;

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

        let points = [
            &e.w[0], &e.w[1], &e.w[2], &e.w[3], &e.w[4], &e.z, &e.t, &e.f, &e.s[0], &e.s[1],
            &e.s[2], &e.s[3], &e.l, &e.lw, &e.h1, &e.h2, &e.tb,
        ];

        for p in &points {
            self.sponge.absorb(p);
        }
    }
}
