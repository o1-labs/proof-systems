use ark_ff::{Field, PrimeField};
use oracle::sponge::{DefaultFrSponge, ScalarChallenge};
use oracle::{
    constants::PlonkSpongeConstantsKimchi as SC,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};

use crate::proof::ProofEvaluations;

pub trait FrSponge<Fr: Field> {
    /// Creates a new Fr-Sponge.
    fn new(p: &'static ArithmeticSpongeParams<Fr>) -> Self;

    /// Absorbs the field element into the sponge.
    fn absorb(&mut self, x: &Fr);

    /// Absorbs a slice of field elements into the sponge.
    fn absorb_multiple(&mut self, x: &[Fr]);

    /// Creates a [`ScalarChallenge`] by squeezing the sponge.
    fn challenge(&mut self) -> ScalarChallenge<Fr>;

    /// Consumes the sponge and returns the current digest, by squeezing.
    fn digest(self) -> Fr;

    /// Absorbs the given evaluations into the sponge.
    // TODO: IMO this function should be inlined in prover/verifier
    fn absorb_evaluations<const N: usize>(&mut self, e: [&ProofEvaluations<Vec<Fr>>; N]);
}

impl<Fr: PrimeField> FrSponge<Fr> for DefaultFrSponge<Fr, SC> {
    fn new(params: &'static ArithmeticSpongeParams<Fr>) -> DefaultFrSponge<Fr, SC> {
        DefaultFrSponge {
            sponge: ArithmeticSponge::new(params),
            last_squeezed: vec![],
        }
    }

    fn absorb(&mut self, x: &Fr) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&[*x]);
    }

    fn absorb_multiple(&mut self, x: &[Fr]) {
        self.last_squeezed = vec![];
        self.sponge.absorb(x);
    }

    fn challenge(&mut self) -> ScalarChallenge<Fr> {
        // TODO: why involve sponge_5_wires here?
        ScalarChallenge(self.squeeze(oracle::sponge::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn digest(mut self) -> Fr {
        self.sponge.squeeze()
    }

    // We absorb all evaluations of the same polynomial at the same time
    fn absorb_evaluations<const N: usize>(&mut self, e: [&ProofEvaluations<Vec<Fr>>; N]) {
        self.last_squeezed = vec![];

        let ProofEvaluations {
            w,
            z,
            s,
            lookup,
            generic_selector,
            poseidon_selector,
        } = ProofEvaluations::transpose(e);

        let mut points = vec![&z, &generic_selector, &poseidon_selector];

        for w in w.iter() {
            points.push(w);
        }
        for s in s.iter() {
            points.push(s);
        }

        if let Some(l) = lookup.as_ref() {
            points.push(&l.aggreg);
            points.push(&l.table);
            for s in &l.sorted {
                points.push(s);
            }
            l.runtime.iter().for_each(|x| points.push(x));
        }

        for p in points {
            for x in p {
                self.sponge.absorb(x);
            }
        }
    }
}
