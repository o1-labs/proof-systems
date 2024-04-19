use crate::{logup::LookupTableID, Logup};
use ark_ff::PrimeField;
use o1_utils::FieldHelpers;
use std::marker::PhantomData;
use strum_macros::EnumIter;

pub mod column;
pub mod constraints;
pub mod interpreter;
pub mod witness;

/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

/// Enumeration of concrete lookup tables used in serialization circuit.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum LookupTable<Ff> {
    /// x ∈ [0, 2^15]
    RangeCheck15,
    /// x ∈ [0, 2^4]
    RangeCheck4,
    /// x ∈ [-2^4, 2^4-1]
    RangeCheck4Abs,
    /// x ∈ [0, ff_highest] where ff_highest is the highest 15-bit
    /// limb of the modulus of the foreign field `Ff`.
    RangeCheckFfHighest(PhantomData<Ff>),
}

impl<Ff: PrimeField> LookupTableID for LookupTable<Ff> {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RangeCheck4 => 2,
            Self::RangeCheck4Abs => 3,
            Self::RangeCheckFfHighest(_) => 4,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::RangeCheck15,
            2 => Self::RangeCheck4,
            3 => Self::RangeCheck4Abs,
            4 => Self::RangeCheckFfHighest(PhantomData),
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
            Self::RangeCheckFfHighest(_) => TryFrom::try_from(
                crate::serialization::interpreter::ff_modulus_highest_limb::<Ff>(),
            )
            .unwrap(),
        }
    }
}

impl<Ff: PrimeField> LookupTable<Ff> {
    pub fn entries_ff_highest<F: PrimeField>(domain_d1_size: u64) -> Vec<F> {
        let top_modulus_f =
            F::from_biguint(&crate::serialization::interpreter::ff_modulus_highest_limb::<Ff>())
                .unwrap();
        (0..domain_d1_size)
            .map(|i| {
                if F::from(i) < top_modulus_f {
                    F::from(i)
                } else {
                    F::zero()
                }
            })
            .collect()
    }

    pub fn entries<F: PrimeField>(&self, domain_d1_size: u64) -> Vec<F> {
        assert!(domain_d1_size >= (1 << 15));
        match self {
            Self::RangeCheck15 => (0..domain_d1_size).map(|i| F::from(i)).collect(),
            Self::RangeCheck4 => (0..domain_d1_size)
                .map(|i| if i < (1 << 4) { F::from(i) } else { F::zero() })
                .collect(),
            Self::RangeCheck4Abs => (0..domain_d1_size)
                .map(|i| {
                    if i < (1 << 4) {
                        // [0,1,2 ... (1<<4)-1]
                        F::from(i)
                    } else if i < 2 * (1 << 4) {
                        // [-(i<<4),...-2,-1]
                        F::from(i - 2 * (1 << 4))
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            Self::RangeCheckFfHighest(_) => Self::entries_ff_highest::<F>(domain_d1_size),
        }
    }
}

impl<Ff: PrimeField> LookupTable<Ff> {}

pub type Lookup<F, Ff> = Logup<F, LookupTable<Ff>>;

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use std::{collections::BTreeMap, marker::PhantomData};

    use super::{Lookup, LookupTable};

    use crate::{
        columns::Column,
        logup::LogupWitness,
        precomputed_srs::get_bn254_srs,
        proof::ProofInputs,
        prover::prove,
        serialization::{
            column::SER_N_COLUMNS,
            constraints,
            interpreter::{
                constrain_multiplication, deserialize_field_element, limb_decompose_ff,
                multiplication_circuit,
            },
            witness, N_INTERMEDIATE_LIMBS,
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

        let mut witness_env = witness::Env::<Fp, Ff1>::create();
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
            let mut constraints_env = constraints::Env::<Fp, Ff1>::create();
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

        let logups: Vec<LogupWitness<Fp, LookupTable<Ff1>>> = lookup_tables
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

        let proof_inputs = ProofInputs {
            evaluations: *witness,
            logups,
        };

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
