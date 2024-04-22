pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod lookups;
pub mod witness;

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use std::{collections::BTreeMap, marker::PhantomData};

    use crate::{
        columns::Column,
        logup::{self, LogupWitness},
        precomputed_srs::get_bn254_srs,
        proof::ProofInputs,
        prover::prove,
        serialization::{
            column::SER_N_COLUMNS,
            constraints::ConstraintBuilderEnv,
            interpreter::{
                constrain_multiplication, deserialize_field_element, limb_decompose_ff,
                multiplication_circuit,
            },
            lookups::{Lookup, LookupTable},
            witness::WitnessBuilderEnv,
            N_INTERMEDIATE_LIMBS,
        },
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254, N_LIMBS,
    };

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        // Must be at least 1 << 15 to support rangecheck15
        const DOMAIN_SIZE: usize = 1 << 15;

        let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut witness_env = WitnessBuilderEnv::<Fp, Ff1>::create();
        // Boxing to avoid stack overflow
        let mut witness: Box<Witness<SER_N_COLUMNS, Vec<Fp>>> = Box::new(Witness {
            cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE))),
        });

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

        // An extra element in the array stands for the fixed table.
        let rangecheck4: [Vec<Lookup<Fp, Ff1>>; N_INTERMEDIATE_LIMBS + 1] =
            std::array::from_fn(|_| vec![]);
        let rangecheck4abs: [Vec<Lookup<Fp, Ff1>>; 6 + 1] = std::array::from_fn(|_| vec![]);
        let rangecheck15: [Vec<Lookup<Fp, Ff1>>; (3 * N_LIMBS - 1) + 1] =
            std::array::from_fn(|_| vec![]);
        let rangecheckffhighest: [Vec<Lookup<Fp, Ff1>>; 1 + 1] = std::array::from_fn(|_| vec![]);

        let mut lookup_tables: BTreeMap<LookupTable<Ff1>, Vec<Vec<Lookup<Fp, Ff1>>>> =
            BTreeMap::new();
        lookup_tables.insert(LookupTable::RangeCheck4, rangecheck4.to_vec());
        lookup_tables.insert(LookupTable::RangeCheck4Abs, rangecheck4abs.to_vec());
        lookup_tables.insert(LookupTable::RangeCheck15, rangecheck15.to_vec());
        lookup_tables.insert(
            LookupTable::RangeCheckFfHighest(PhantomData),
            rangecheckffhighest.to_vec(),
        );

        for (_i, limbs) in field_elements.iter().enumerate() {
            // Witness
            deserialize_field_element(&mut witness_env, limbs.map(Into::into));
            multiplication_circuit(&mut witness_env, input_chal, coeff_input, false);
            // Filling actually used rows
            for j in 0..SER_N_COLUMNS {
                witness.cols[j].push(witness_env.witness.cols[j]);
            }

            for (table_id, table) in lookup_tables.iter_mut() {
                //println!("Processing table id {:?}", table_id);
                for (j, lookup) in witness_env
                    .lookups
                    .get(table_id)
                    .unwrap()
                    .iter()
                    .enumerate()
                {
                    table[j].push(lookup.clone())
                }
            }

            witness_env.reset()
        }

        let constraints = {
            let mut constraints_env = ConstraintBuilderEnv::<Fp, Ff1>::create();
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

        let mut lookup_multiplicities: BTreeMap<LookupTable<Ff1>, Vec<Fp>> = BTreeMap::new();
        // Counting multiplicities & adding fixed column into the last column of every table.
        for (table_id, table) in lookup_tables.iter_mut() {
            let lookup_m = witness_env.get_lookup_multiplicities(domain, *table_id);
            lookup_multiplicities.insert(*table_id, lookup_m.clone());
            let lookup_t = (*table_id)
                .entries(domain.d1.size)
                .into_iter()
                .enumerate()
                .map(|(i, v)| Lookup {
                    table_id: *table_id,
                    numerator: -lookup_m[i],
                    value: vec![v],
                });
            *(table.last_mut().unwrap()) = lookup_t.collect();
        }

        let lookups: Vec<LogupWitness<Fp, LookupTable<Ff1>>> = lookup_tables
            .iter()
            .filter_map(|(table_id, table)| {
                // Only add a table if it's used. Otherwise lookups fail.
                if !table.is_empty() && !table[0].is_empty() {
                    Some(LogupWitness {
                        f: table.clone(),
                        m: lookup_multiplicities[table_id].clone(),
                        table_id: *table_id,
                    })
                } else {
                    None
                }
            })
            .collect();

        // FIXME
        let fixed_lookup_tables = BTreeMap::new();

        let logup_inputs = logup::prover::Inputs {
            lookups,
            fixed_lookup_tables: fixed_lookup_tables.clone(),
        };

        let proof_inputs = ProofInputs {
            evaluations: *witness,
            logups: Some(logup_inputs),
        };

        let public_inputs = Witness::zero_vec(DOMAIN_SIZE);
        let logup_index = Some(logup::verifier::Index {
            fixed_lookup_tables,
        });

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
            public_inputs,
            logup_index,
            &proof,
        );
        assert!(verifies)
    }
}
