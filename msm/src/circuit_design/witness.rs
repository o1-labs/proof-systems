use crate::{
    circuit_design::capabilities::{
        ColAccessCap, ColWriteCap, DirectWitnessCap, HybridCopyCap, LookupCap, MultiRowReadCap,
    },
    columns::{Column, ColumnIndexer},
    logup::{Logup, LogupWitness, LookupTableID},
    proof::ProofInputs,
    witness::Witness,
};
use ark_ff::PrimeField;
use log::debug;
use std::{
    collections::{BTreeMap, HashSet},
    iter,
    marker::PhantomData,
};

/// Witness builder environment. Operates on multiple rows at the same
/// time. `CIx::N_COL` must be equal to `N_WIT + N_FSEL`; passing these two
/// separately is due to a rust limitation.
pub struct WitnessBuilderEnv<
    F: PrimeField,
    CIx: ColumnIndexer,
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    LT: LookupTableID,
> {
    /// The witness columns that the environment is working with.
    /// Every element of the vector is a row, and the builder is
    /// always processing the last row.
    pub witness: Vec<Witness<N_WIT, F>>,

    /// Lookup multiplicities, a vector of values `m_i` per lookup
    /// table, where `m_i` is how many times the lookup value number
    /// `i` was looked up.
    pub lookup_multiplicities: BTreeMap<LT, Vec<F>>,

    /// Lookup requests. Each vector element represents one row, and
    /// each row is a map from lookup type to a vector of concrete
    /// lookups requested.
    pub lookups: Vec<BTreeMap<LT, Vec<Logup<F, LT>>>>,

    /// Fixed values for selector columns. `fixed_selectors[i][j]` is the
    /// value for row #j of the selector #i.
    pub fixed_selectors: Vec<Vec<F>>,

    /// Function used to map assertions.
    pub assert_mapper: Box<dyn Fn(F) -> F>,

    /// History of all cells written.
    pub cells_written: HashSet<(usize, Column)>,

    // A Phantom Data for CIx -- right now WitnessBUilderEnv does not
    // depend on CIx, but in the future (with associated generics
    // enabled?) it might be convenient to put all the `NT_COL` (and
    // other) constants into `CIx`. Logically, all these constants
    // "belong" to CIx, so there's an extra type parameter, and a
    // phantom data to support it.
    pub phantom_cix: PhantomData<CIx>,
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > ColAccessCap<F, CIx> for WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    // Requiring an F element as we would need to compute values up to 180 bits
    // in the 15 bits decomposition.
    type Variable = F;

    fn assert_zero(&mut self, cst: Self::Variable) {
        assert_eq!((self.assert_mapper)(cst), F::zero());
    }

    fn set_assert_mapper(&mut self, mapper: Box<dyn Fn(Self::Variable) -> Self::Variable>) {
        self.assert_mapper = mapper;
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn read_column(&self, ix: CIx) -> Self::Variable {
        match ix.to_column() {
            Column::Relation(i) => self.witness.last().unwrap().cols[i],
            Column::FixedSelector(i) => self.fixed_selectors[i][self.witness.len() - 1],
            other => panic!("WitnessBuilderEnv::read_column does not support {other:?}"),
        }
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > ColWriteCap<F, CIx> for WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    fn write_column(&mut self, ix: CIx, value: &Self::Variable) {
        assert!(
            !self
                .cells_written
                .contains(&(self.curr_row(), ix.to_column())),
            "double write at {:?} {:?}",
            self.curr_row(),
            ix.to_column()
        );
        self.cells_written.insert((self.curr_row(), ix.to_column()));
        self.write_column_raw(ix.to_column(), *value);
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
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > HybridCopyCap<F, CIx> for WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    fn hcopy(&mut self, value: &Self::Variable, ix: CIx) -> Self::Variable {
        <WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT> as ColWriteCap<F, CIx>>::write_column(
            self, ix, value,
        );
        *value
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > MultiRowReadCap<F, CIx> for WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    /// Read value from a (row,column) position.
    fn read_row_column(&mut self, row: usize, col: CIx) -> Self::Variable {
        let Column::Relation(i) = col.to_column() else {
            todo!()
        };
        self.witness[row].cols[i]
    }

    /// Progresses to the next row.
    fn next_row(&mut self) {
        self.next_row();
    }

    /// Returns the current row.
    fn curr_row(&self) -> usize {
        self.witness.len() - 1
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > DirectWitnessCap<F, CIx> for WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    /// Convert an abstract variable to a field element! Inverse of Env::constant().
    fn variable_to_field(value: Self::Variable) -> F {
        value
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > LookupCap<F, CIx, LT> for WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
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

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    pub fn write_column_raw(&mut self, position: Column, value: F) {
        match position {
            Column::Relation(i) => self.witness.last_mut().unwrap().cols[i] = value,
            Column::FixedSelector(_) => {
                panic!("Witness environment can't write into fixed selector columns.");
            }
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
            cols: Box::new([F::zero(); N_WIT]),
        });
        let mut lookups_row = BTreeMap::new();
        for table_id in LT::all_variants().into_iter() {
            lookups_row.insert(table_id, Vec::new());
        }
        self.lookups.push(lookups_row);
    }

    /// Getting multiplicities for range check tables less or equal than 15 bits.
    pub fn get_lookup_multiplicities(&self, domain_size: usize, table_id: LT) -> Vec<F> {
        let mut m = Vec::with_capacity(domain_size);
        m.extend(self.lookup_multiplicities[&table_id].to_vec());
        if table_id.length() < domain_size {
            let n_repeated_dummy_value: usize = domain_size - table_id.length() - 1;
            let repeated_dummy_value: Vec<F> = iter::repeat(-F::one())
                .take(n_repeated_dummy_value)
                .collect();
            m.extend(repeated_dummy_value);
            m.push(F::from(n_repeated_dummy_value as u64));
        }
        assert_eq!(m.len(), domain_size);
        m
    }
}

impl<
        F: PrimeField,
        CIx: ColumnIndexer,
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        LT: LookupTableID,
    > WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    /// Create a new empty-state witness builder.
    pub fn create() -> Self {
        let mut lookups_row = BTreeMap::new();
        let mut lookup_multiplicities = BTreeMap::new();
        let fixed_selectors = vec![vec![]; N_FSEL];
        for table_id in LT::all_variants().into_iter() {
            lookups_row.insert(table_id, Vec::new());
            lookup_multiplicities.insert(table_id, vec![F::zero(); table_id.length()]);
        }

        Self {
            witness: vec![Witness {
                cols: Box::new([F::zero(); N_WIT]),
            }],

            lookup_multiplicities,
            lookups: vec![lookups_row],
            fixed_selectors,
            cells_written: HashSet::new(),
            assert_mapper: Box::new(|x| x),
            phantom_cix: PhantomData,
        }
    }

    /// Sets a fixed selector, the vector of length equal to the
    /// domain size (circuit height).
    pub fn set_fixed_selector_cix(&mut self, sel: CIx, sel_values: Vec<F>) {
        if let Column::FixedSelector(i) = sel.to_column() {
            self.fixed_selectors[i] = sel_values;
        } else {
            panic!("Tried to assign values to non-fixed-selector typed column {sel:?}");
        }
    }

    /// Sets all fixed selectors directly. Each item in `selectors` is
    /// a vector of `domain_size` length.
    pub fn set_fixed_selectors(&mut self, selectors: Vec<Vec<F>>) {
        self.fixed_selectors = selectors
    }

    pub fn get_relation_witness(&self, domain_size: usize) -> Witness<N_WIT, Vec<F>> {
        // Boxing to avoid stack overflow
        let mut witness: Box<Witness<N_WIT, Vec<F>>> = Box::new(Witness {
            cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(domain_size))),
        });

        // Filling actually used rows first
        for witness_row in self.witness.iter().take(domain_size) {
            for j in 0..N_REL {
                witness.cols[j].push(witness_row.cols[j]);
            }
        }

        // Then filling witness rows up with zeroes to the domain size
        // FIXME: Maybe this is not always wise, as default instance can be non-zero.
        if self.witness.len() < domain_size {
            for i in 0..N_REL {
                witness.cols[i].extend(vec![F::zero(); domain_size - self.witness.len()]);
            }
        }

        // Fill out dynamic selectors.
        for i in 0..N_DSEL {
            // TODO FIXME Fill out dynamic selectors!
            witness.cols[N_REL + i] = vec![F::zero(); domain_size];
        }

        for i in 0..(N_REL + N_DSEL) {
            assert!(
                witness.cols[i].len() == domain_size,
                "Witness columns length {:?} for column {:?} does not match domain size {:?}",
                witness.cols[i].len(),
                i,
                domain_size
            );
        }

        *witness
    }

    pub fn get_logup_witness(
        &self,
        domain_size: usize,
        lookup_tables_data: BTreeMap<LT, Vec<F>>,
    ) -> Vec<LogupWitness<F, LT>> {
        // Building lookup values
        let mut lookup_tables: BTreeMap<LT, Vec<Vec<Logup<F, LT>>>> = BTreeMap::new();
        if !lookup_tables_data.is_empty() {
            for table_id in LT::all_variants().into_iter() {
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
            let lookup_m = self.get_lookup_multiplicities(domain_size, *table_id);
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

        lookup_tables
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
            .collect()
    }

    /// Generates proof inputs, repacking/collecting internal witness builder state.
    pub fn get_proof_inputs(
        &self,
        domain_size: usize,
        lookup_tables_data: BTreeMap<LT, Vec<F>>,
    ) -> ProofInputs<N_WIT, F, LT> {
        let evaluations = self.get_relation_witness(domain_size);
        let logups = self.get_logup_witness(domain_size, lookup_tables_data);

        ProofInputs {
            evaluations,
            logups,
        }
    }
}
