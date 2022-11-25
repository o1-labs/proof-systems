use ark_ff::{Field, PrimeField};
use mina_poseidon::sponge::{DefaultFrSponge, ScalarChallenge};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};

use crate::proof::{PointEvaluations, ProofEvaluations};

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

        let mut points = vec![
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
            &e.coefficients[0],
            &e.coefficients[1],
            &e.coefficients[2],
            &e.coefficients[3],
            &e.coefficients[4],
            &e.coefficients[5],
            &e.coefficients[6],
            &e.coefficients[7],
            &e.coefficients[8],
            &e.coefficients[9],
            &e.coefficients[10],
            &e.coefficients[11],
            &e.coefficients[12],
            &e.coefficients[13],
            &e.coefficients[14],
            &e.s[0],
            &e.s[1],
            &e.s[2],
            &e.s[3],
            &e.s[4],
            &e.s[5],
        ];

        if let Some(l) = e.lookup.as_ref() {
            points.push(&l.aggreg);
            points.push(&l.table);
            for s in &l.sorted {
                points.push(s);
            }
            l.runtime.iter().for_each(|x| points.push(x));
        }

        for p in points {
            self.sponge.absorb(&p.zeta);
            self.sponge.absorb(&p.zeta_omega);
        }
    }
}
