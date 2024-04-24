pub mod column;
pub mod interpreter;
pub mod lookups;

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use std::collections::BTreeMap;
    use strum::IntoEnumIterator;

    use crate::{
        circuit_design::{constraints::ConstraintBuilderEnv, witness::WitnessBuilderEnv},
        columns::{Column, ColumnIndexer},
        precomputed_srs::get_bn254_srs,
        prover::prove,
        serialization::{
            column::{SerializationColumn, SER_N_COLUMNS},
            interpreter::{
                constrain_multiplication, deserialize_field_element, limb_decompose_ff,
                multiplication_circuit,
            },
            lookups::LookupTable,
        },
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        // Must be at least 1 << 15 to support rangecheck15
        const DOMAIN_SIZE: usize = 1 << 15;

        let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut witness_env = WitnessBuilderEnv::<
            Fp,
            { <SerializationColumn as ColumnIndexer>::COL_N },
            LookupTable<Ff1>,
        >::create();

        // Boxing to avoid stack overflow
        let mut field_elements = vec![];

        // FIXME: we do use always the same values here, because we have a
        // constant check (X - c), different for each row. And there is no
        // constant support/public input yet in the quotient polynomial.
        let input_chal: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
        let [input1, input2, input3]: [Fp; 3] = limb_decompose_ff::<Fp, Ff1, 88, 3>(&input_chal);
        for _ in 0..DOMAIN_SIZE {
            field_elements.push([input1, input2, input3])
        }
        let coeff_input: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);

        let constraints = {
            let mut constraints_env = ConstraintBuilderEnv::<Fp, LookupTable<Ff1>>::create();
            deserialize_field_element(&mut constraints_env, field_elements[0].map(Into::into));
            constrain_multiplication(&mut constraints_env);

            // Sanity checks.
            assert!(constraints_env.lookups[&LookupTable::RangeCheck15].len() == (3 * 17 - 1));
            assert!(constraints_env.lookups[&LookupTable::RangeCheck4].len() == 20);
            assert!(constraints_env.lookups[&LookupTable::RangeCheck4Abs].len() == 6);
            assert!(
                constraints_env.lookups
                    [&LookupTable::RangeCheckFfHighest(std::marker::PhantomData)]
                    .len()
                    == 1
            );

            constraints_env.get_constraints()
        };

        for (i, limbs) in field_elements.iter().enumerate() {
            // Witness
            deserialize_field_element(&mut witness_env, limbs.map(Into::into));
            multiplication_circuit(&mut witness_env, input_chal, coeff_input, false);

            // Don't reset on the last iteration.
            if i < DOMAIN_SIZE {
                witness_env.next_row()
            }
        }

        // Fixed tables can be generated inside lookup_tables_data. Runtime should be generated here.
        let mut lookup_tables_data = BTreeMap::new();
        for table_id in LookupTable::<Ff1>::iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data);

        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            SER_N_COLUMNS,
            LookupTable<Ff1>,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            SER_N_COLUMNS,
            0,
            LookupTable<Ff1>,
        >(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(DOMAIN_SIZE),
        );
        assert!(verifies)
    }
}
