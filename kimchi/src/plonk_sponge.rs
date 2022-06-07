use ark_ff::{Field, PrimeField};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};
use oracle::{
    constants::PlonkSpongeConstantsKimchi as SC,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};

use crate::proof::ProofEvaluations;

pub trait FrSponge<Fr: Field> {
    /// Creates a new Fr-Sponge.
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;

    /// Absorbs the field element into the sponge.
    fn absorb(&mut self, x: &Fr);

    /// Creates a [ScalarChallenge] by squeezing the sponge.
    fn challenge(&mut self) -> ScalarChallenge<Fr>;

    /// Absorbs the given evaluations into the sponge.
    // TODO: IMO this function should be inlined in prover/verifier
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

        if let Some(lookup) = &e.lookup {
            for s in &lookup.sorted {
                self.sponge.absorb(s);
            }
            self.sponge.absorb(&lookup.aggreg);
            self.sponge.absorb(&lookup.table);

            if let Some(runtime_table) = &lookup.runtime {
                self.sponge.absorb(runtime_table);
            }
        }
    }
}
