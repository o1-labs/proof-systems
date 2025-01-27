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
                limb_decompose_ff, serialization_circuit,
            },
            lookups::LookupTable,
        },
        Ff1, Fp,
    };

    type SerializationWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        SerializationColumn,
        { <SerializationColumn as ColumnIndexer<usize>>::N_COL - N_FSEL_SER },
        { <SerializationColumn as ColumnIndexer<usize>>::N_COL - N_FSEL_SER },
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

        let mut field_elements = vec![];

        // FIXME: we do use always the same values here, because we have a
        // constant check (X - c), different for each row. And there is no
        // constant support/public input yet in the quotient polynomial.
        let input_chal: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
        let [input1, input2, input3]: [Fp; 3] = limb_decompose_ff::<Fp, Ff1, 88, 3>(&input_chal);
        for _ in 0..domain_size {
            field_elements.push([input1, input2, input3])
        }

        let constraints = {
            let mut constraints_env = ConstraintBuilderEnv::<Fp, LookupTable<Ff1>>::create();
            deserialize_field_element(&mut constraints_env, field_elements[0].map(Into::into));
            constrain_multiplication(&mut constraints_env);

            // Sanity checks.
            assert!(constraints_env.lookup_reads[&LookupTable::RangeCheck15].len() == (3 * 17 - 1));
            assert!(constraints_env.lookup_reads[&LookupTable::RangeCheck4].len() == 20);
            assert!(constraints_env.lookup_reads[&LookupTable::RangeCheck9Abs].len() == 6);
            assert!(
                constraints_env.lookup_reads
                    [&LookupTable::RangeCheckFfHighest(std::marker::PhantomData)]
                    .len()
                    == 1
            );

            constraints_env.get_constraints()
        };

        serialization_circuit(&mut witness_env, input_chal, field_elements, domain_size);

        let runtime_tables: BTreeMap<_, Vec<Vec<Vec<_>>>> =
            witness_env.get_runtime_tables(domain_size);

        // TODO remove this clone
        // Fixed tables can be generated inside lookup_tables_data. Runtime should be generated here.
        let multiplication_bus: Vec<Vec<Vec<Fp>>> = runtime_tables
            .get(&LookupTable::MultiplicationBus)
            .unwrap()
            .clone();

        //assert!(multiplication_bus.len() == 2);

        let mut lookup_tables_data: BTreeMap<LookupTable<Ff1>, Vec<Vec<Vec<Fp>>>> = BTreeMap::new();
        for table_id in LookupTable::<Ff1>::all_variants().into_iter() {
            if table_id.is_fixed() {
                lookup_tables_data.insert(
                    table_id,
                    vec![table_id
                        .entries(domain_size as u64)
                        .unwrap()
                        .into_iter()
                        .map(|x| vec![x])
                        .collect()],
                );
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
