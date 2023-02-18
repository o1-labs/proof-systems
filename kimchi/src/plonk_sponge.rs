use ark_ff::{Field, PrimeField};
use mina_poseidon::sponge::{DefaultFrSponge, ScalarChallenge};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};

use crate::proof::{LookupEvaluations, PointEvaluations, ProofEvaluations};

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
    fn absorb_evaluations(&mut self, e: &ProofEvaluations<PointEvaluations<Vec<Fr>>>);
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
    fn absorb_evaluations(&mut self, e: &ProofEvaluations<PointEvaluations<Vec<Fr>>>) {
        self.last_squeezed = vec![];

        let ProofEvaluations {
            w,
            z,
            s,
            coefficients,
            lookup,
            generic_selector,
            poseidon_selector,
            additive_lookup_aggregation,
            additive_lookup_count,
            additive_lookup_inverses,
        } = e;

        let mut points = vec![z, generic_selector, poseidon_selector];
        w.iter().for_each(|w_i| points.push(w_i));
        coefficients.iter().for_each(|c_i| points.push(c_i));
        s.iter().for_each(|s_i| points.push(s_i));

        if let Some(l) = lookup.as_ref() {
            let LookupEvaluations {
                table,
                runtime,
            } = l;
            points.push(table);
            runtime.iter().for_each(|x| points.push(x));
        }

        points.extend(additive_lookup_aggregation.iter());
        points.extend(additive_lookup_count.iter());
        points.extend(additive_lookup_inverses.iter().flat_map(|x| x.iter()));

        points.into_iter().for_each(|p| {
            self.sponge.absorb(&p.zeta);
            self.sponge.absorb(&p.zeta_omega);
        })
    }
}
