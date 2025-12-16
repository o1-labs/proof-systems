use ark_ff::{Field, PrimeField};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC,
    poseidon::Sponge,
    sponge::{DefaultFrSponge, ScalarChallenge},
};

use crate::proof::{PointEvaluations, ProofEvaluations};

/// Abstracts a sponge that operates on the scalar field of an
/// elliptic curve. Unlike the [`FqSponge`](mina_poseidon::FqSponge)
/// it cannot absorb or digest base field elements. However, the
/// [`FqSponge`](mina_poseidon::FqSponge) can *also* operate on the
/// scalar field by the means of a specific encoding technique.
pub trait FrSponge<Fr: Field> {
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

impl<const FULL_ROUNDS: usize, Fr: PrimeField> FrSponge<Fr>
    for DefaultFrSponge<Fr, SC, FULL_ROUNDS>
{
    fn absorb(&mut self, x: &Fr) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&[*x]);
    }

    fn absorb_multiple(&mut self, x: &[Fr]) {
        self.last_squeezed = vec![];
        self.sponge.absorb(x);
    }

    fn challenge(&mut self) -> ScalarChallenge<Fr> {
        ScalarChallenge(self.squeeze(mina_poseidon::sponge::CHALLENGE_LENGTH_IN_LIMBS))
    }

    fn digest(mut self) -> Fr {
        self.sponge.squeeze()
    }

    // We absorb all evaluations of the same polynomial at the same time
    fn absorb_evaluations(&mut self, e: &ProofEvaluations<PointEvaluations<Vec<Fr>>>) {
        self.last_squeezed = vec![];

        let ProofEvaluations {
            public: _, // Must be absorbed first manually for now, to handle Mina annoyances
            w,
            z,
            s,
            coefficients,
            generic_selector,
            poseidon_selector,
            complete_add_selector,
            mul_selector,
            emul_selector,
            endomul_scalar_selector,
            range_check0_selector,
            range_check1_selector,
            foreign_field_add_selector,
            foreign_field_mul_selector,
            xor_selector,
            rot_selector,
            lookup_aggregation,
            lookup_table,
            lookup_sorted,
            runtime_lookup_table,
            runtime_lookup_table_selector,
            xor_lookup_selector,
            lookup_gate_lookup_selector,
            range_check_lookup_selector,
            foreign_field_mul_lookup_selector,
        } = e;

        let mut points = vec![
            z,
            generic_selector,
            poseidon_selector,
            complete_add_selector,
            mul_selector,
            emul_selector,
            endomul_scalar_selector,
        ];
        w.iter().for_each(|w_i| points.push(w_i));
        coefficients.iter().for_each(|c_i| points.push(c_i));
        s.iter().for_each(|s_i| points.push(s_i));

        // Optional gates

        if let Some(range_check0_selector) = range_check0_selector.as_ref() {
            points.push(range_check0_selector)
        }
        if let Some(range_check1_selector) = range_check1_selector.as_ref() {
            points.push(range_check1_selector)
        }
        if let Some(foreign_field_add_selector) = foreign_field_add_selector.as_ref() {
            points.push(foreign_field_add_selector)
        }
        if let Some(foreign_field_mul_selector) = foreign_field_mul_selector.as_ref() {
            points.push(foreign_field_mul_selector)
        }
        if let Some(xor_selector) = xor_selector.as_ref() {
            points.push(xor_selector)
        }
        if let Some(rot_selector) = rot_selector.as_ref() {
            points.push(rot_selector)
        }
        if let Some(lookup_aggregation) = lookup_aggregation.as_ref() {
            points.push(lookup_aggregation)
        }
        if let Some(lookup_table) = lookup_table.as_ref() {
            points.push(lookup_table)
        }
        for lookup_sorted in lookup_sorted {
            if let Some(lookup_sorted) = lookup_sorted.as_ref() {
                points.push(lookup_sorted)
            }
        }
        if let Some(runtime_lookup_table) = runtime_lookup_table.as_ref() {
            points.push(runtime_lookup_table)
        }
        if let Some(runtime_lookup_table_selector) = runtime_lookup_table_selector.as_ref() {
            points.push(runtime_lookup_table_selector)
        }
        if let Some(xor_lookup_selector) = xor_lookup_selector.as_ref() {
            points.push(xor_lookup_selector)
        }
        if let Some(lookup_gate_lookup_selector) = lookup_gate_lookup_selector.as_ref() {
            points.push(lookup_gate_lookup_selector)
        }
        if let Some(range_check_lookup_selector) = range_check_lookup_selector.as_ref() {
            points.push(range_check_lookup_selector)
        }
        if let Some(foreign_field_mul_lookup_selector) = foreign_field_mul_lookup_selector.as_ref()
        {
            points.push(foreign_field_mul_lookup_selector)
        }

        points.into_iter().for_each(|p| {
            self.sponge.absorb(&p.zeta);
            self.sponge.absorb(&p.zeta_omega);
        })
    }
}
