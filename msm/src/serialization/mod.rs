use ark_ff::Field;

use crate::mvlookup::LookupTableID;

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod witness;

pub enum LookupTable {
    RangeCheck15,
    RangeCheck4,
}

impl LookupTableID for LookupTable {
    fn into_field<F: Field>(self) -> F {
        match self {
            Self::RangeCheck15 => F::one(),
            Self::RangeCheck4 => F::one() + F::one(),
        }
    }
}

#[cfg(test)]
mod tests {
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::Rng as _;

    use crate::{
        columns::Column,
        lookups::LookupTableIDs,
        precomputed_srs::get_bn254_srs,
        proof::ProofInputs,
        prover::prove,
        serialization::{
            constraints, interpreter::deserialize_field_element, witness, N_INTERMEDIATE_LIMBS,
        },
        verifier::verify,
        witness::Witness,
        BaseSponge, Fp, OpeningProof, ScalarSponge, BN254, N_LIMBS,
    };

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        // Must be at least 1 << 15 to support rangecheck15
        const DOMAIN_SIZE: usize = 1 << 15;

        const SERIALIZATION_N_COLUMNS: usize = 3 + N_INTERMEDIATE_LIMBS + N_LIMBS;

        let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut witness_env = witness::Env::<Fp>::create();
        // Boxing to avoid stack overflow
        let mut witness: Box<Witness<SERIALIZATION_N_COLUMNS, Vec<Fp>>> = Box::new(Witness {
            cols: std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE)),
        });

        // Boxing to avoid stack overflow
        let field_elements = Box::new(
            [[
                rng.gen_range(0..1000),
                rng.gen_range(0..1000),
                rng.gen_range(0..1000),
            ]; DOMAIN_SIZE],
        );

        let mut constraints = vec![];
        for limbs in *field_elements {
            let mut constraint_env = constraints::Env::<Fp>::create();
            // Witness
            deserialize_field_element(&mut witness_env, limbs);
            for i in 0..3 {
                witness.cols[i].push(witness_env.current_kimchi_limbs[i]);
            }
            for i in 0..N_LIMBS {
                witness.cols[3 + i].push(witness_env.msm_limbs[i]);
            }
            for i in 0..N_INTERMEDIATE_LIMBS {
                witness.cols[3 + N_LIMBS + i].push(witness_env.intermediate_limbs[i]);
            }

            // Constraints
            deserialize_field_element(&mut constraint_env, limbs);
            // FIXME: do not use clone.
            // FIXME: this is ugly, but only to make it work for now.
            // It does suppose the same constraint aalways have the same index.
            // Totally wrong assumption according to the current env implementation.
            for (idx, cst) in constraint_env.constraints.iter() {
                if *idx >= constraints.len() {
                    constraints.push(cst.clone())
                }
            }
        }

        let proof_inputs = ProofInputs {
            evaluations: *witness,
            mvlookups: vec![],
            public_input_size: 0,
        };

        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            SERIALIZATION_N_COLUMNS,
            LookupTableIDs,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, SERIALIZATION_N_COLUMNS>(
            domain,
            &srs,
            &constraints,
            &proof,
        );
        assert!(verifies)
    }
}
