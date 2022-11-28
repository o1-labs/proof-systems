use ark_ff::{Field, PrimeField};
use mina_poseidon::sponge::{DefaultFrSponge, ScalarChallenge};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};

use crate::proof::{LookupEvaluations, ProofEvaluations};

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
        ScalarChallenge(self.squeeze(mina_poseidon::sponge::CHALLENGE_LENGTH_IN_LIMBS))
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
            coefficients,
            lookup,
            generic_selector,
            poseidon_selector,
        } = ProofEvaluations::transpose(e);

        let mut points = vec![
            &z,
            &generic_selector,
            &poseidon_selector,
            &w[0],
            &w[1],
            &w[2],
            &w[3],
            &w[4],
            &w[5],
            &w[6],
            &w[7],
            &w[8],
            &w[9],
            &w[10],
            &w[11],
            &w[12],
            &w[13],
            &w[14],
            &coefficients[0],
            &coefficients[1],
            &coefficients[2],
            &coefficients[3],
            &coefficients[4],
            &coefficients[5],
            &coefficients[6],
            &coefficients[7],
            &coefficients[8],
            &coefficients[9],
            &coefficients[10],
            &coefficients[11],
            &coefficients[12],
            &coefficients[13],
            &coefficients[14],
            &s[0],
            &s[1],
            &s[2],
            &s[3],
            &s[4],
            &s[5],
        ];

        if let Some(l) = lookup.as_ref() {
            let LookupEvaluations {
                sorted,
                aggreg,
                table,
                runtime,
            } = l;
            points.push(aggreg);
            points.push(table);
            for s in sorted {
                points.push(s);
            }
            runtime.iter().for_each(|x| points.push(x));
        }

        for p in points {
            for x in p {
                self.sponge.absorb(x);
            }
        }
    }
}
