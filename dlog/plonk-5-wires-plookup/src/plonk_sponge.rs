use plonk_5_wires_plookup_circuits::scalars::ProofEvaluations;
use algebra::{
    Field, PrimeField,
};
use oracle::poseidon_5_wires::{ArithmeticSponge, PlonkSpongeConstants as SC};
use oracle::poseidon::{ArithmeticSpongeParams, Sponge};
use oracle::sponge_5_wires::{DefaultFrSponge, ScalarChallenge};

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> ScalarChallenge<Fr>;
    fn absorb_evaluations(&mut self, p: &[Fr], e: &ProofEvaluations<Vec<Fr>>);
}

impl<Fr: PrimeField> FrSponge<Fr> for DefaultFrSponge<Fr, SC> {
    fn new(params: ArithmeticSpongeParams<Fr>) -> DefaultFrSponge<Fr, SC> {
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
        ScalarChallenge(self.squeeze(oracle::sponge_5_wires::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn absorb_evaluations(&mut self, p: &[Fr], e: &ProofEvaluations<Vec<Fr>>) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&self.params, p);

        let points = [
            &e.w[0],
            &e.w[1],
            &e.w[2],
            &e.w[3],
            &e.w[4],
            &e.z,
            &e.t,
            &e.f,
            &e.s[0],
            &e.s[1],
            &e.s[2],
            &e.s[3],
            &e.l,
            &e.lw,
            &e.h1,
            &e.h2,
            &e.tb,
        ];

        for p in &points {
            self.sponge.absorb(&self.params, p);
        }
    }
}
