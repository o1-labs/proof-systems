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
    fn absorb_evaluations<const N: usize>(
        &mut self,
        p: [&[Fr]; N],
        evals: [&ProofEvaluations<Fr>; N],
    );
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

    // We absorb all evaluations of the same polynomial at the same time
    fn absorb_evaluations<const N: usize>(
        &mut self,
        p: [&[Fr]; N],
        evals: [&ProofEvaluations<Fr>; N],
    ) {
        self.last_squeezed = vec![];
        for x in p {
            self.sponge.absorb(x);
        }

        let zeta_evals = &evals[0];
        let zeta_omega_evals = &evals[1];

        let mut points = vec![
            zeta_evals.z,
            zeta_omega_evals.z,
            zeta_evals.generic_selector,
            zeta_omega_evals.generic_selector,
            zeta_evals.poseidon_selector,
            zeta_omega_evals.poseidon_selector,
            zeta_evals.w[0],
            zeta_omega_evals.w[0],
            zeta_evals.w[1],
            zeta_omega_evals.w[1],
            zeta_evals.w[2],
            zeta_omega_evals.w[2],
            zeta_evals.w[3],
            zeta_omega_evals.w[3],
            zeta_evals.w[4],
            zeta_omega_evals.w[4],
            zeta_evals.w[5],
            zeta_omega_evals.w[5],
            zeta_evals.w[6],
            zeta_omega_evals.w[6],
            zeta_evals.w[7],
            zeta_omega_evals.w[7],
            zeta_evals.w[8],
            zeta_omega_evals.w[8],
            zeta_evals.w[9],
            zeta_omega_evals.w[9],
            zeta_evals.w[10],
            zeta_omega_evals.w[10],
            zeta_evals.w[11],
            zeta_omega_evals.w[11],
            zeta_evals.w[12],
            zeta_omega_evals.w[12],
            zeta_evals.w[13],
            zeta_omega_evals.w[13],
            zeta_evals.w[14],
            zeta_omega_evals.w[14],
            zeta_evals.s[0],
            zeta_omega_evals.s[0],
            zeta_evals.s[1],
            zeta_omega_evals.s[1],
            zeta_evals.s[2],
            zeta_omega_evals.s[2],
            zeta_evals.s[3],
            zeta_omega_evals.s[3],
            zeta_evals.s[4],
            zeta_omega_evals.s[4],
            zeta_evals.s[5],
            zeta_omega_evals.s[5],
        ];

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
