use crate::{mvlookup::LookupTableID, MVLookup};

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod witness;

#[derive(Clone, Copy, Debug)]
pub enum LookupTable {
    RangeCheck15,
    RangeCheck4,
}

impl LookupTableID for LookupTable {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RangeCheck4 => 2,
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::RangeCheck15 => 1 << 15,
            Self::RangeCheck4 => 1 << 4,
        }
    }
}

pub type Lookup<F> = MVLookup<F, LookupTable>;

#[cfg(test)]
mod tests {
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::Rng as _;

    use super::{Lookup, LookupTable};

    use crate::{
        columns::Column,
        mvlookup::MVLookupWitness,
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

    use ark_ff::{FftField, Field, PrimeField};

    impl LookupTable {
        fn into_lookup_vector<F: FftField + PrimeField + Field>(
            self,
            domain: EvaluationDomains<F>,
        ) -> Vec<Lookup<F>> {
            assert!(domain.d1.size >= (1 << 15));
            match self {
                Self::RangeCheck15 => (0..(1 << 15))
                    .map(|i| Lookup {
                        table_id: LookupTable::RangeCheck15,
                        numerator: -F::one(),
                        value: vec![F::from(i as u64)],
                    })
                    .collect::<Vec<Lookup<F>>>(),
                Self::RangeCheck4 => (0..(1 << 15))
                    .map(|i| {
                        if i < (1 << 4) {
                            F::from(i as u64)
                        } else {
                            F::zero()
                        }
                    })
                    .map(|x| Lookup {
                        table_id: LookupTable::RangeCheck4,
                        numerator: -F::one(),
                        value: vec![x],
                    })
                    .collect::<Vec<Lookup<F>>>(),
            }
        }
    }

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
        let mut field_elements = vec![];
        // FIXME: we do use always the same values here, because we have a
        // constant check (X - c), different for each row. And there is no
        // constant support/public input yet in the quotient polynomial.
        let (x, y, z) = (
            rng.gen_range(0..1000000),
            rng.gen_range(0..1000000),
            rng.gen_range(0..1000000),
        );
        for _ in 0..DOMAIN_SIZE {
            field_elements.push([x, y, z])
        }

        let mut constraints = vec![];

        // Adding one for the fixed table.
        let mut rangecheck15: [Vec<Lookup<Fp>>; N_LIMBS + 1] = std::array::from_fn(|_| vec![]);
        let mut rangecheck4: [Vec<Lookup<Fp>>; N_INTERMEDIATE_LIMBS + 1] =
            std::array::from_fn(|_| vec![]);

        for (i, limbs) in field_elements.into_iter().enumerate() {
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

            for (j, lookup) in witness_env.rangecheck4_lookups.iter().enumerate() {
                rangecheck4[j].push(lookup.clone())
            }

            for (j, lookup) in witness_env.rangecheck15_lookups.iter().enumerate() {
                rangecheck15[j].push(lookup.clone())
            }

            witness_env.add_rangecheck4_table_value(i);

            witness_env.reset()
        }

        let rangecheck15_m = witness_env.get_rangecheck15_normalized_multipliticies(domain);
        let rangecheck15_t = LookupTable::RangeCheck15
            .into_lookup_vector(domain)
            .into_iter()
            .enumerate()
            .map(
                |(
                    i,
                    Lookup {
                        table_id,
                        numerator,
                        value,
                    },
                )| {
                    Lookup {
                        table_id,
                        numerator: numerator * rangecheck15_m[i],
                        value,
                    }
                },
            );
        rangecheck15[N_LIMBS] = rangecheck15_t.collect();

        let rangecheck4_m = witness_env.get_rangecheck4_normalized_multipliticies(domain);
        let rangecheck4_t = LookupTable::RangeCheck4
            .into_lookup_vector(domain)
            .into_iter()
            .enumerate()
            .map(
                |(
                    i,
                    Lookup {
                        table_id,
                        numerator,
                        value,
                    },
                )| {
                    Lookup {
                        table_id,
                        numerator: numerator * rangecheck4_m[i],
                        value,
                    }
                },
            );
        rangecheck4[N_INTERMEDIATE_LIMBS] = rangecheck4_t.collect();

        let lookup_witness_rangecheck4: MVLookupWitness<Fp, LookupTable> = {
            MVLookupWitness {
                f: rangecheck4.to_vec(),
                m: rangecheck4_m,
            }
        };

        let lookup_witness_rangecheck15: MVLookupWitness<Fp, LookupTable> = {
            MVLookupWitness {
                f: rangecheck15.to_vec(),
                m: rangecheck15_m,
            }
        };

        let proof_inputs = ProofInputs {
            evaluations: *witness,
            mvlookups: vec![lookup_witness_rangecheck15, lookup_witness_rangecheck4],
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
            LookupTable,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            SERIALIZATION_N_COLUMNS,
            0,
            LookupTable,
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
