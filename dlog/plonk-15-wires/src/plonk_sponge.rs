use algebra::{Field, PrimeField};
use plonk_15_wires_circuits::nolookup::scalars::ProofEvaluations;
// use oracle::poseidon_5_wires::{ArithmeticSponge, PlonkSpongeConstants as SC};
use oracle::poseidon::{
    ArithmeticSponge, ArithmeticSpongeParams, Plonk15SpongeConstants as SC, Sponge,
};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};

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
            &e.w[0], &e.w[1], &e.w[2], &e.w[3], &e.w[4], &e.z, &e.t, &e.f, &e.s[0], &e.s[1],
            &e.s[2], &e.s[3],
        ];

        for p in &points {
            self.sponge.absorb(&self.params, p);
        }
    }
}
