use ark_ff::{Field, PrimeField};
use oracle::poseidon::{ArithmeticSponge, PlonkSpongeConstants as SC};
use oracle::poseidon::{ArithmeticSpongeParams, Sponge};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};
use plonk_15_wires_circuits::lookup::scalars::ProofEvaluations;

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
            &e.pe.w[0], &e.pe.w[1], &e.pe.w[2], &e.pe.w[3], &e.pe.w[4], &e.pe.z, &e.pe.t, &e.pe.f,
            &e.pe.s[0], &e.pe.s[1], &e.pe.s[2], &e.pe.s[3], &e.l, &e.lw, &e.h1, &e.h2, &e.tb,
        ];

        for p in &points {
            self.sponge.absorb(p);
        }
    }
}
