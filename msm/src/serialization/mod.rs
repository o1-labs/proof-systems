pub mod column;
pub mod interpreter;
pub mod lookups;

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use std::collections::BTreeMap;

    use crate::{
        circuit_design::{constraints::ConstraintBuilderEnv, witness::WitnessBuilderEnv},
        columns::ColumnIndexer,
        logup::LookupTableID,
        serialization::{
            column::{SerializationColumn, N_COL_SER, N_FSEL_SER},
            interpreter::{
                build_selectors, constrain_multiplication, deserialize_field_element,
                limb_decompose_ff, multiplication_circuit,
            },
            lookups::LookupTable,
        },
        Ff1, Fp,
    };

    type SerializationWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        SerializationColumn,
        { <SerializationColumn as ColumnIndexer>::N_COL - N_FSEL_SER },
        { <SerializationColumn as ColumnIndexer>::N_COL - N_FSEL_SER },
        0,
        N_FSEL_SER,
        LookupTable<Ff1>,
    >;

    #[test]
    fn heavy_test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // Must be at least 1 << 15 to support rangecheck15
        let domain_size: usize = 1 << 15;

        let mut witness_env = SerializationWitnessBuilderEnv::create();

        let fixed_selectors = build_selectors(domain_size);
        witness_env.set_fixed_selectors(fixed_selectors.to_vec());

        // Boxing to avoid stack overflow
        let mut field_elements = vec![];

        // FIXME: we do use always the same values here, because we have a
        // constant check (X - c), different for each row. And there is no
        // constant support/public input yet in the quotient polynomial.
        let input_chal: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
        let [input1, input2, input3]: [Fp; 3] = limb_decompose_ff::<Fp, Ff1, 88, 3>(&input_chal);
        for _ in 0..domain_size {
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
            assert!(constraints_env.lookups[&LookupTable::RangeCheck9Abs].len() == 6);
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
            if i < domain_size {
                witness_env.next_row()
            }
        }

        // Fixed tables can be generated inside lookup_tables_data. Runtime should be generated here.
        let multiplication_bus: Vec<Fp> = vec![];
        let mut lookup_tables_data = BTreeMap::new();
        for table_id in LookupTable::<Ff1>::all_variants().into_iter() {
            if table_id.is_fixed() {
                lookup_tables_data.insert(table_id, table_id.entries(domain_size as u64).unwrap());
            }
        }
        lookup_tables_data.insert(LookupTable::MultiplicationBus, multiplication_bus);
        let proof_inputs = witness_env.get_proof_inputs(domain_size, lookup_tables_data);

        crate::test::test_completeness_generic::<
            { N_COL_SER - N_FSEL_SER },
            { N_COL_SER - N_FSEL_SER },
            0,
            N_FSEL_SER,
            LookupTable<Ff1>,
            _,
        >(
            constraints,
            Box::new(fixed_selectors),
            proof_inputs,
            domain_size,
            &mut rng,
        );
    }
}
