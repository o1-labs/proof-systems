use ark_ff::{Field, PrimeField};
use itertools::Itertools;
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

    /// Creates a [ScalarChallenge] by squeezing the sponge.
    fn challenge(&mut self) -> ScalarChallenge<Fr>;

    /// Consumes the sponge and returns the current digest, by squeezing.
    fn digest(self) -> Fr;

    /// Absorbs the given evaluations into the sponge.
    // TODO: IMO this function should be inlined in prover/verifier
    fn absorb_evaluations<const N: usize>(&mut self, evals: [&ProofEvaluations<Fr>; N]);
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
    fn absorb_evaluations<const N: usize>(&mut self, evals: [&ProofEvaluations<Fr>; N]) {
        self.last_squeezed = vec![];

        let zeta_evals = &evals[0];
        let zeta_omega_evals = &evals[1];

        // we interleave points from each evaluations,
        // it makes it easier to absorb them in the verifier circuit
        let mut points: Vec<_> = zeta_evals
            .iter()
            .interleave(zeta_omega_evals.iter())
            .collect();

        // TODO: shouldn't we check in the index that lookup is set? where do we verify that lookup stuff is set in the proof if it's set in the verifier index?
        if let Some((l0, l1)) = zeta_evals
            .lookup
            .as_ref()
            .zip(zeta_omega_evals.lookup.as_ref())
        {
            points.extend(&[l0.aggreg, l1.aggreg]);
            points.extend(&[l0.table, l1.table]);

            for (s0, s1) in l0.sorted.iter().zip(&l1.sorted) {
                points.extend(&[*s0, *s1]);
            }

            for (r0, r1) in l0.runtime.iter().zip(&l1.runtime) {
                points.extend(&[*r0, *r1]);
            }
        }

        self.sponge.absorb(&points);
    }
}
