use plonk_circuits::scalars::ProofEvaluations;
use algebra::{
    Field, PairingEngine, PrimeField,
};

use oracle::{sponge::{DefaultFrSponge, FqSponge, ScalarChallenge}, poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge, PlonkSpongeConstants as SC}};

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> ScalarChallenge<Fr>;
    fn absorb_evaluations(&mut self, e: &ProofEvaluations<Fr>);
}

pub trait SpongePairingEngine: PairingEngine {
    type FqSponge: FqSponge<Self::Fq, Self::G1Affine, Self::Fr>;
    type FrSponge: FrSponge<Self::Fr>;
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
        ScalarChallenge(self.squeeze(oracle::sponge::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn absorb_evaluations(&mut self, e: &ProofEvaluations<Fr>) {
        self.last_squeezed = vec![];

        let points = [
            e.l,
            e.r,
            e.o,
            e.sigma1,
            e.sigma2,
            e.r,
            e.z,
        ];

        for p in &points {
            self.sponge.absorb(&self.params, &[*p]);
        }
    }
}
