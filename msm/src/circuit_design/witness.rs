use crate::{
    circuit_design::capabilities::{ColAccessCap, ColWriteCap, HybridCopyCap, LookupCap},
    columns::{Column, ColumnIndexer},
    logup::{Logup, LogupWitness, LookupTableID},
    proof::ProofInputs,
    witness::Witness,
};
use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use log::debug;
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
    > ColAccessCap<F, CIx> for WitnessBuilderEnv<F, CIX_COL_N, LT>
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
        let Column::Relation(i) = ix.to_column() else {
            todo!()
        };
        self.witness.last().unwrap().cols[i]
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const CIX_COL_N: usize,
        LT: LookupTableID + IntoEnumIterator,
    > ColWriteCap<F, CIx> for WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    fn write_column(&mut self, ix: CIx, value: &Self::Variable) {
        let Column::Relation(i) = ix.to_column() else {
            todo!()
        };
        self.witness.last_mut().unwrap().cols[i] = *value;
    }
}

/// If `Env` implements real write ("for sure" writes), you can implement
/// hybrid copy (that is only required to "maybe" copy). The other way
/// around violates the semantics.
///
/// Sadly, rust does not allow "cover" instances to define this impl
/// for every `T: ColWriteCap`.
impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const CIX_COL_N: usize,
        LT: LookupTableID + IntoEnumIterator,
    > HybridCopyCap<F, CIx> for WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    fn hcopy(&mut self, value: &Self::Variable, ix: CIx) -> Self::Variable {
        <WitnessBuilderEnv<F, CIX_COL_N, LT> as ColWriteCap<F, CIx>>::write_column(self, ix, value);
        *value
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const CIX_COL_N: usize,
        LT: LookupTableID + IntoEnumIterator,
    > LookupCap<F, CIx, LT> for WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    fn lookup(&mut self, table_id: LT, value: &<Self as ColAccessCap<F, CIx>>::Variable) {
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
}

impl<F: PrimeField, const CIX_COL_N: usize, LT: LookupTableID + IntoEnumIterator>
    WitnessBuilderEnv<F, CIX_COL_N, LT>
{
    pub fn write_column(&mut self, position: Column, value: F) {
        match position {
            Column::Relation(i) => self.witness.last_mut().unwrap().cols[i] = value,
            Column::DynamicSelector(_) => {
                // TODO: Do we want to allow writing to dynamic selector columns only 1 or 0?
                panic!(
                    "This is a dynamic selector column. The environment is
                supposed to write only in witness columns"
                );
            }
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

        // Filling actually used rows first
        for witness_row in self.witness.iter().take(domain_size) {
            for j in 0..CIX_COL_N {
                witness.cols[j].push(witness_row.cols[j]);
            }
        }
        // Then filling witness rows up with zeroes to the domain size
        // FIXME: Maybe this is not always wise, as default instance can be non-zero.
        if self.witness.len() < domain_size {
            for i in 0..CIX_COL_N {
                witness.cols[i].extend(vec![F::zero(); domain_size - self.witness.len()]);
            }
        }

        // Building lookup values
        let mut lookup_tables: BTreeMap<LT, Vec<Vec<Logup<F, LT>>>> = BTreeMap::new();
        if !lookup_tables_data.is_empty() {
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
        } else {
            debug!("No lookup tables data provided. Skipping lookup tables.");
        }

        for lookup_row in self.lookups.iter().take(domain_size) {
            for (table_id, table) in lookup_tables.iter_mut() {
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
