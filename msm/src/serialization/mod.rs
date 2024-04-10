use crate::{mvlookup::LookupTableID, Ff1, Ff2, MVLookup, LIMB_BITSIZE, N_LIMBS};
use ark_ff::{FpParameters, PrimeField};
use num_bigint::BigUint;

pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod witness;

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum LookupTable {
    RangeCheck15,
    RangeCheck4,
    RangeCheck4Abs,
    RangeCheckFf1Highest,
    RangeCheckFf2Highest,
}

impl LookupTableID for LookupTable {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RangeCheck4 => 2,
            Self::RangeCheck4Abs => 3,
            Self::RangeCheckFf1Highest => 4,
            Self::RangeCheckFf2Highest => 5,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::RangeCheck15,
            2 => Self::RangeCheck4,
            3 => Self::RangeCheck4Abs,
            4 => Self::RangeCheckFf1Highest,
            5 => Self::RangeCheckFf2Highest,
            _ => panic!("Invalid lookup table id"),
        }
    }

    /// All tables are fixed tables.
    fn is_fixed(&self) -> bool {
        true
    }

    fn length(&self) -> usize {
        match self {
            Self::RangeCheck15 => 1 << 15,
            Self::RangeCheck4 => 1 << 4,
            Self::RangeCheck4Abs => 1 << 5,
            Self::RangeCheckFf1Highest => TryFrom::try_from(Self::ff_modulus::<Ff1>()).unwrap(),
            Self::RangeCheckFf2Highest => TryFrom::try_from(Self::ff_modulus::<Ff2>()).unwrap(),
        }
    }
}

impl LookupTable {
    fn ff_modulus<Ff: PrimeField>() -> BigUint {
        let f_bui: BigUint = TryFrom::try_from(<Ff as PrimeField>::Params::MODULUS).unwrap();
        f_bui >> ((N_LIMBS - 1) * LIMB_BITSIZE)
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
            column::SER_N_COLUMNS, constraints, interpreter::deserialize_field_element, witness,
            N_INTERMEDIATE_LIMBS,
        },
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Ff2, Fp, OpeningProof, ScalarSponge, BN254, N_LIMBS,
    };

    use ark_ff::PrimeField;
    use o1_utils::FieldHelpers;

    impl LookupTable {
        fn entries_ff_modulus<F: PrimeField, Ff: PrimeField>(
            domain: EvaluationDomains<F>,
        ) -> Vec<F> {
            let top_modulus_f = F::from_biguint(&Self::ff_modulus::<Ff>()).unwrap();
            (0..domain.d1.size)
                .map(|i| {
                    if F::from(i) < top_modulus_f {
                        F::from(i)
                    } else {
                        F::zero()
                    }
                })
                .collect()
        }

        fn entries<F: PrimeField>(&self, domain: EvaluationDomains<F>) -> Vec<F> {
            assert!(domain.d1.size >= (1 << 15));
            match self {
                Self::RangeCheck15 => (0..domain.d1.size).map(|i| F::from(i)).collect(),
                Self::RangeCheck4 => (0..domain.d1.size)
                    .map(|i| if i < (1 << 4) { F::from(i) } else { F::zero() })
                    .collect(),
                Self::RangeCheck4Abs => (0..domain.d1.size)
                    .map(|i| {
                        if i < (1 << 4) {
                            F::from(i)
                        } else if i < 2 * (i << 4) {
                            F::from((1 << 4) - i)
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
                Self::RangeCheckFf1Highest => Self::entries_ff_modulus::<F, Ff1>(domain),
                Self::RangeCheckFf2Highest => Self::entries_ff_modulus::<F, Ff2>(domain),
            }
        }
    }

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        // Must be at least 1 << 15 to support rangecheck15
        const DOMAIN_SIZE: usize = 1 << 15;

        let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut witness_env = witness::Env::<Fp>::create();
        // Boxing to avoid stack overflow
        let mut witness: Box<Witness<SER_N_COLUMNS, Vec<Fp>>> = Box::new(Witness {
            cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE))),
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

        // Adding one for the fixed table.
        let mut rangecheck15: [Vec<Lookup<Fp>>; N_LIMBS + 1] = std::array::from_fn(|_| vec![]);
        let mut rangecheck4: [Vec<Lookup<Fp>>; N_INTERMEDIATE_LIMBS + 1] =
            std::array::from_fn(|_| vec![]);

        for (_i, limbs) in field_elements.iter().enumerate() {
            // Witness
            deserialize_field_element(&mut witness_env, *limbs);
            // Filling actually used rows
            for j in 0..SER_N_COLUMNS {
                witness.cols[j].push(witness_env.witness.cols[j]);
            }

            for (j, lookup) in witness_env
                .lookups
                .get(&LookupTable::RangeCheck4)
                .unwrap()
                .iter()
                .enumerate()
            {
                rangecheck4[j].push(lookup.clone())
            }

            for (j, lookup) in witness_env
                .lookups
                .get(&LookupTable::RangeCheck15)
                .unwrap()
                .iter()
                .enumerate()
            {
                rangecheck15[j].push(lookup.clone())
            }

            witness_env.reset()
        }

        let constraints = {
            let mut constraints_env = constraints::Env::<Fp>::create();
            deserialize_field_element(&mut constraints_env, field_elements[0]);
            constraints_env.get_constraints()
        };

        let rangecheck15_m = witness_env.get_rangecheck15_multipliticies(domain);
        let rangecheck15_t = LookupTable::RangeCheck15
            .entries(domain)
            .into_iter()
            .enumerate()
            .map(|(i, v)| Lookup {
                table_id: LookupTable::RangeCheck15,
                numerator: -rangecheck15_m[i],
                value: vec![v],
            });
        rangecheck15[N_LIMBS] = rangecheck15_t.collect();

        let rangecheck4_m = witness_env.get_rangecheck4_multipliticies(domain);
        let rangecheck4_t = LookupTable::RangeCheck4
            .entries(domain)
            .into_iter()
            .enumerate()
            .map(|(i, v)| Lookup {
                table_id: LookupTable::RangeCheck4,
                numerator: -rangecheck4_m[i],
                value: vec![v],
            });
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
        };

        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            SER_N_COLUMNS,
            LookupTable,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        let verifies =
            verify::<_, OpeningProof, BaseSponge, ScalarSponge, SER_N_COLUMNS, 0, LookupTable>(
                domain,
                &srs,
                &constraints,
                &proof,
                Witness::zero_vec(DOMAIN_SIZE),
            );
        assert!(verifies)
    }
}
