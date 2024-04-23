use crate::{
    columns::{Column, ColumnIndexer},
    logup::{Logup, LogupWitness, LookupTableID},
    proof::ProofInputs,
    serialization::interpreter::InterpreterEnv,
    witness::Witness,
};
use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use o1_utils::FieldHelpers;
use std::{collections::BTreeMap, iter};
use strum::IntoEnumIterator;

/// Witness builder environment. Operates
pub struct WitnessBuilderEnv<F: PrimeField, const CIX_COL_N: usize, LT: LookupTableID> {
    /// The witness columns that the environment is working with.
    /// Every element of the vector is a row, and the builder is
    /// always processing the last row.
    pub witness: Vec<Witness<CIX_COL_N, F>>,

    /// Lookup multiplicities, a vector of values `m_i` per lookup
    /// table, where `m_i` is how many times the lookup value number
    /// `i` was looked up.
    pub lookup_multiplicities: BTreeMap<LT, Vec<F>>,

    /// Lookup requests. Each vector element represents one row, and
    /// each row is a map from lookup type to a vector of concrete
    /// lookups requested.
    pub lookups: Vec<BTreeMap<LT, Vec<Logup<F, LT>>>>,
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const CIX_COL_N: usize,
        LT: LookupTableID + IntoEnumIterator,
    > InterpreterEnv<F, CIx, LT> for WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    // Requiring an F element as we would need to compute values up to 180 bits
    // in the 15 bits decomposition.
    type Variable = F;

    fn assert_zero(&mut self, cst: Self::Variable) {
        assert_eq!(cst, F::zero());
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn read_column(&self, ix: CIx) -> Self::Variable {
        let Column::X(i) = ix.to_column() else {
            todo!()
        };
        self.witness.last().unwrap().cols[i]
    }

    fn lookup(&mut self, table_id: LT, value: &Self::Variable) {
        let value_ix = table_id.ix_by_value(*value);
        self.lookup_multiplicities.get_mut(&table_id).unwrap()[value_ix] += F::one();
        self.lookups
            .last_mut()
            .unwrap()
            .get_mut(&table_id)
            .unwrap()
            .push(Logup {
                table_id,
                numerator: F::one(),
                value: vec![*value],
            })
    }

    fn copy(&mut self, x: &Self::Variable, position: CIx) -> Self::Variable {
        self.write_column(position.to_column(), *x);
        *x
    }

    // TODO this does not belong in the generic interpreter, move out.
    /// Returns the bits between [highest_bit, lowest_bit] of the variable `x`,
    /// and copy the result in the column `position`.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: CIx,
    ) -> Self::Variable {
        // FIXME: we can assume bitmask_be will be called only on value with
        // maximum 128 bits. We use bitmask_be only for the limbs
        let x_bytes_u8 = &x.to_bytes()[0..16];
        let x_u128 = u128::from_le_bytes(x_bytes_u8.try_into().unwrap());
        let res = (x_u128 >> lowest_bit) & ((1 << (highest_bit - lowest_bit)) - 1);
        let res_fp: F = res.into();
        self.write_column(position.to_column(), res_fp);
        res_fp
    }
}

impl<F: PrimeField, const CIX_COL_N: usize, LT: LookupTableID + IntoEnumIterator>
    WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    fn write_column(&mut self, position: Column, value: F) {
        match position {
            Column::X(i) => self.witness.last_mut().unwrap().cols[i] = value,
            Column::LookupPartialSum(_) => {
                panic!(
                    "This is a lookup related column. The environment is
                supposed to write only in witness columns"
                );
            }
            Column::LookupMultiplicity(_) => {
                panic!(
                    "This is a lookup related column. The environment is
                supposed to write only in witness columns"
                );
            }
            Column::LookupAggregation => {
                panic!(
                    "This is a lookup related column. The environment is
                supposed to write only in witness columns"
                );
            }
            Column::LookupFixedTable(_) => {
                panic!(
                    "This is a lookup related column. The environment is
                supposed to write only in witness columns"
                );
            }
        }
    }

    /// Progress to the computations on the next row.
    pub fn next_row(&mut self) {
        self.witness.push(Witness {
            cols: Box::new([F::zero(); CIX_COL_N]),
        });
        let mut lookups_row = BTreeMap::new();
        for table_id in LT::iter() {
            lookups_row.insert(table_id, Vec::new());
        }
        self.lookups.push(lookups_row);
    }

    /// Getting multiplicities for range check tables less or equal than 15 bits.
    pub fn get_lookup_multiplicities(&self, domain: EvaluationDomains<F>, table_id: LT) -> Vec<F> {
        let mut m = Vec::with_capacity(domain.d1.size as usize);
        m.extend(self.lookup_multiplicities[&table_id].to_vec());
        if table_id.length() < (domain.d1.size as usize) {
            let n_repeated_dummy_value: usize = (domain.d1.size as usize) - table_id.length() - 1;
            let repeated_dummy_value: Vec<F> = iter::repeat(-F::one())
                .take(n_repeated_dummy_value)
                .collect();
            m.extend(repeated_dummy_value);
            m.push(F::from(n_repeated_dummy_value as u64));
        }
        assert_eq!(m.len(), domain.d1.size as usize);
        m
    }
}

impl<F: PrimeField, const CIX_COL_N: usize, LT: LookupTableID + IntoEnumIterator>
    WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    /// Create a new empty-state witness builder.
    pub fn create() -> Self {
        let mut lookups_row = BTreeMap::new();
        let mut lookup_multiplicities = BTreeMap::new();
        for table_id in LT::iter() {
            lookups_row.insert(table_id, Vec::new());
            lookup_multiplicities.insert(table_id, vec![F::zero(); table_id.length()]);
        }

        Self {
            witness: vec![Witness {
                cols: Box::new([F::zero(); CIX_COL_N]),
            }],

            lookup_multiplicities,
            lookups: vec![lookups_row],
        }
    }

    /// Generates proof inputs, repacking/collecting internal witness builder state.
    pub fn get_proof_inputs(
        &self,
        domain: EvaluationDomains<F>,
        lookup_tables_data: BTreeMap<LT, Vec<F>>,
    ) -> ProofInputs<CIX_COL_N, F, LT> {
        let domain_size: usize = domain.d1.size as usize;
        // Boxing to avoid stack overflow
        let mut witness: Box<Witness<CIX_COL_N, Vec<F>>> = Box::new(Witness {
            cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
        });

        let mut lookup_tables: BTreeMap<LT, Vec<Vec<Logup<F, LT>>>> = BTreeMap::new();
        for table_id in LT::iter() {
            // Find how many lookups are done per table.
            let number_of_lookups = self.lookups[0].get(&table_id).unwrap().len();
            // Technically the number of lookups must be the same per
            // row, but let's check if it's actually so.
            for (i, lookup_row) in self.lookups.iter().enumerate().take(domain_size) {
                let number_of_lookups_currow = lookup_row.get(&table_id).unwrap().len();
                assert!(
                    number_of_lookups == number_of_lookups_currow,
                    "Different number of lookups in row {i:?} and row 0: {number_of_lookups_currow:?} vs {number_of_lookups:?}"
                );
            }
            // +1 for the fixed table
            lookup_tables.insert(table_id, vec![vec![]; number_of_lookups + 1]);
        }

        for witness_row in self.witness.iter().take(domain_size) {
            // Filling actually used rows
            for j in 0..CIX_COL_N {
                witness.cols[j].push(witness_row.cols[j]);
            }
        }

        for lookup_row in self.lookups.iter().take(domain_size) {
            for (table_id, table) in lookup_tables.iter_mut() {
                //println!("Processing table id {:?}", table_id);
                for (j, lookup) in lookup_row.get(table_id).unwrap().iter().enumerate() {
                    table[j].push(lookup.clone())
                }
            }
        }

        let mut lookup_multiplicities: BTreeMap<LT, Vec<F>> = BTreeMap::new();
        // Counting multiplicities & adding fixed column into the last column of every table.
        for (table_id, table) in lookup_tables.iter_mut() {
            let lookup_m = self.get_lookup_multiplicities(domain, *table_id);
            lookup_multiplicities.insert(*table_id, lookup_m.clone());
            let lookup_t = lookup_tables_data[table_id]
                .iter()
                .enumerate()
                .map(|(i, v)| Logup {
                    table_id: *table_id,
                    numerator: -lookup_m[i],
                    value: vec![*v],
                });
            *(table.last_mut().unwrap()) = lookup_t.collect();
        }

        let logups: Vec<LogupWitness<F, LT>> = lookup_tables
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

        ProofInputs {
            evaluations: *witness,
            logups,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        columns::ColumnIndexer,
        serialization::{
            column::SerializationColumn,
            interpreter::{deserialize_field_element, InterpreterEnv},
            lookups::LookupTable,
            witness::WitnessBuilderEnv,
            N_INTERMEDIATE_LIMBS,
        },
        Ff1, LIMB_BITSIZE, N_LIMBS,
    };
    use ark_ff::{BigInteger, FpParameters as _, One, PrimeField, UniformRand, Zero};
    use mina_curves::pasta::Fp;
    use num_bigint::BigUint;
    use o1_utils::{tests::make_test_rng, FieldHelpers};
    use rand::Rng;
    use std::str::FromStr;

    fn test_decomposition_generic(x: Fp) {
        let bits = x.to_bits();
        let limb0: u128 = {
            let limb0_le_bits: &[bool] = &bits.clone().into_iter().take(88).collect::<Vec<bool>>();
            let limb0 = Fp::from_bits(limb0_le_bits).unwrap();
            limb0.to_biguint().try_into().unwrap()
        };
        let limb1: u128 = {
            let limb0_le_bits: &[bool] = &bits
                .clone()
                .into_iter()
                .skip(88)
                .take(88)
                .collect::<Vec<bool>>();
            let limb0 = Fp::from_bits(limb0_le_bits).unwrap();
            limb0.to_biguint().try_into().unwrap()
        };
        let limb2: u128 = {
            let limb0_le_bits: &[bool] = &bits
                .clone()
                .into_iter()
                .skip(2 * 88)
                .take(79)
                .collect::<Vec<bool>>();
            let limb0 = Fp::from_bits(limb0_le_bits).unwrap();
            limb0.to_biguint().try_into().unwrap()
        };
        let mut dummy_env = WitnessBuilderEnv::<
            Fp,
            { <SerializationColumn as ColumnIndexer>::COL_N },
            LookupTable<Ff1>,
        >::create();
        deserialize_field_element(
            &mut dummy_env,
            [
                BigUint::from(limb0),
                BigUint::from(limb1),
                BigUint::from(limb2),
            ],
        );

        // Check limb are copied into the environment
        let limbs_to_assert = [limb0, limb1, limb2];
        for (i, limb) in limbs_to_assert.iter().enumerate() {
            assert_eq!(
                Fp::from(*limb),
                dummy_env.read_column(SerializationColumn::ChalKimchi(i))
            );
        }

        // Check intermediate limbs
        {
            let bits = Fp::from(limb2).to_bits();
            for j in 0..N_INTERMEDIATE_LIMBS {
                let le_bits: &[bool] = &bits
                    .clone()
                    .into_iter()
                    .skip(j * 4)
                    .take(4)
                    .collect::<Vec<bool>>();
                let t = Fp::from_bits(le_bits).unwrap();
                let intermediate_v =
                    dummy_env.read_column(SerializationColumn::ChalIntermediate(j));
                assert_eq!(
                    t,
                    intermediate_v,
                    "{}",
                    format_args!(
                        "Intermediate limb {j}. Exp value is {:?}, computed is {:?}",
                        t.to_biguint(),
                        intermediate_v.to_biguint()
                    )
                )
            }
        }

        // Checking msm limbs
        for i in 0..N_LIMBS {
            let le_bits: &[bool] = &bits
                .clone()
                .into_iter()
                .skip(i * LIMB_BITSIZE)
                .take(LIMB_BITSIZE)
                .collect::<Vec<bool>>();
            let t = Fp::from_bits(le_bits).unwrap();
            let converted_v = dummy_env.read_column(SerializationColumn::ChalConverted(i));
            assert_eq!(
                t,
                converted_v,
                "{}",
                format_args!(
                    "MSM limb {i}. Exp value is {:?}, computed is {:?}",
                    t.to_biguint(),
                    converted_v.to_biguint()
                )
            )
        }
    }

    #[test]
    fn test_decomposition_zero() {
        test_decomposition_generic(Fp::zero());
    }

    #[test]
    fn test_decomposition_one() {
        test_decomposition_generic(Fp::one());
    }

    #[test]
    fn test_decomposition_random_first_limb_only() {
        let mut rng = make_test_rng();
        let x = rng.gen_range(0..2u128.pow(88) - 1);
        test_decomposition_generic(Fp::from(x));
    }

    #[test]
    fn test_decomposition_second_limb_only() {
        test_decomposition_generic(Fp::from(2u128.pow(88)));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 1));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 2));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 16));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 23234));
    }

    #[test]
    fn test_decomposition_random_second_limb_only() {
        let mut rng = make_test_rng();
        let x = rng.gen_range(0..2u128.pow(88) - 1);
        test_decomposition_generic(Fp::from(2u128.pow(88) + x));
    }

    #[test]
    fn test_decomposition_random() {
        let mut rng = make_test_rng();
        test_decomposition_generic(Fp::rand(&mut rng));
    }

    #[test]
    fn test_decomposition_order_minus_one() {
        let x = BigUint::from_bytes_be(&<Fp as PrimeField>::Params::MODULUS.to_bytes_be())
            - BigUint::from_str("1").unwrap();

        test_decomposition_generic(Fp::from(x));
    }
}
