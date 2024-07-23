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
use std::{collections::BTreeMap, iter, marker::PhantomData};

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
    pub lookup_multiplicities: BTreeMap<LT, Vec<u64>>,

    // @volhovm: It seems much more ineffective to store
    // Vec<BTreeMap<LT, Vec<Logup>>> than BTreeMap<LT, Vec<Vec<Logup>>>.
    /// Lookup requests. Each vector element represents one row, and
    /// each row is a map from lookup type to a vector of concrete
    /// lookups requested.
    pub lookup_reads: Vec<BTreeMap<LT, Vec<Logup<F, LT>>>>,

    /// For each runtime lookup table, the vector of requested values.
    /// We assume one read lookup per row at the moment.
    pub runtime_lookups: BTreeMap<LT, Vec<Vec<F>>>,

    // This includes runtime tables which do not /need/ an explicit
    // column, so it is duplicated in `witness` in this case.
    /// Values for runtime tables. Each element (value) in the map is
    /// a set of on-the-fly built columns, one column per write.
    /// - `runtime_tables[table_id][write_i]` is a column corresponding to a write #`write_i` per row.
    /// - `runtime_tables[table_id][write_i][row_i]` is a value-vector that's looked up at `row_i`
    pub runtime_tables: BTreeMap<LT, Vec<Vec<Vec<F>>>>,

    /// Fixed values for selector columns. `fixed_selectors[i][j]` is the
    /// value for row #j of the selector #i.
    pub fixed_selectors: Vec<Vec<F>>,

    /// Function used to map assertions.
    pub assert_mapper: Box<dyn Fn(F) -> F>,

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
    fn lookup(&mut self, table_id: LT, value: Vec<<Self as ColAccessCap<F, CIx>>::Variable>) {
        if table_id.is_fixed() {
            let value_ix = table_id
                .ix_by_value(&value)
                .expect("Could not resolve lookup for a fixed table");

            let multiplicities = self.lookup_multiplicities.get_mut(&table_id).unwrap();
            // Since we allow multiple lookups per row, runtime tables
            // can in theory grow bigger than the domain size. We
            // still collect multiplicities as if runtime table vector
            // is not height-bounded, but we will split it into chunks
            // later.
            if !table_id.is_fixed() && value_ix > multiplicities.len() {
                multiplicities.resize(value_ix, 0u64);
            }
            multiplicities[value_ix] += 1;

            self.lookup_reads
                .last_mut()
                .unwrap()
                .get_mut(&table_id)
                .unwrap()
                .push(Logup {
                    table_id,
                    numerator: F::one(),
                    value,
                })
        } else {
            //println!("Reading id {table_id:?}, value {value:?}");

            self.runtime_lookups.get_mut(&table_id).unwrap().push(value)
        }
    }

    fn lookup_runtime_write(&mut self, table_id: LT, value: Vec<Self::Variable>) {
        assert!(
            !table_id.is_fixed() && !table_id.runtime_create_column(),
            "lookup_runtime_write must be called on non-fixed tables that work with dynamic writes only"
        );

        //println!("Writing id {table_id:?}, value {value:?}");

        // We insert value into runtime table in any case, for each row.
        let cur_row = self.witness.len();

        let runtime_table = self.runtime_tables.get_mut(&table_id).unwrap();

        let cur_write_number = (0..runtime_table.len()).find(|i| runtime_table[*i].len() < cur_row);

        let cur_write_number = if let Some(v) = cur_write_number {
            v
        } else {
            assert!(
                cur_row == 0,
                "Number of writes in row {cur_row:?} is different from row 0"
            );
            runtime_table.push(vec![]);
            runtime_table.len() - 1
        };

        runtime_table[cur_write_number].push(value);
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
        self.lookup_reads.push(lookups_row);
    }

    /// Getting multiplicities for range check tables less or equal
    /// than 15 bits. Return value is a vector of columns, where each
    /// column represents a "read". Fixed lookup tables always return
    /// a single-column vector, while runtime tables may return more.
    pub fn get_lookup_multiplicities(&self, domain_size: usize, table_id: LT) -> Vec<Vec<F>> {
        if table_id.is_fixed() {
            let mut m = Vec::with_capacity(domain_size);
            m.extend(
                self.lookup_multiplicities[&table_id]
                    .iter()
                    .map(|x| F::from(*x)),
            );
            if table_id.length() < domain_size {
                let n_repeated_dummy_value: usize = domain_size - table_id.length() - 1;
                let repeated_dummy_value: Vec<F> = iter::repeat(-F::one())
                    .take(n_repeated_dummy_value)
                    .collect();
                m.extend(repeated_dummy_value);
                m.push(F::from(n_repeated_dummy_value as u64));
            }
            assert_eq!(m.len(), domain_size);
            vec![m]
        } else {
            // For runtime tables, multiplicities are computed post
            // factum, since we explicitly want (e.g. for RAM lookups)
            // reads and writes to be parallel -- in many cases we
            // haven't previously written the value we want to read.

            let runtime_table = self.runtime_tables.get(&table_id).unwrap();
            let num_writes = runtime_table.len();

            // A runtime table resolver; the inverse of `runtime_tables`:
            // maps runtime lookup table to `(column, row)`
            let mut resolver: BTreeMap<Vec<F>, (usize, usize)> = BTreeMap::new();

            {
                // Populate resolver map either from "reads" or from "writes"
                if table_id.runtime_create_column() {
                    assert!(num_writes == 0);

                    for (row_i, value) in self
                        .runtime_lookups
                        .get(&table_id)
                        .unwrap()
                        .iter()
                        .enumerate()
                    {
                        if resolver.get_mut(value).is_none() {
                            resolver.insert(value.clone(), (0, row_i));
                        }
                    }
                } else {
                    for col_i in 0..num_writes {
                        for (row_i, value) in runtime_table[col_i].iter().enumerate() {
                            if resolver.get_mut(value).is_none() {
                                resolver.insert(value.clone(), (col_i, row_i));
                            }
                        }
                    }
                }
            }

            // Resolve reads and build multiplicities vector

            let mut multiplicities = vec![vec![0u64; domain_size]; num_writes];

            for value in self.runtime_lookups.get(&table_id).unwrap().iter() {
                if let Some((col_i, row_i)) = resolver.get_mut(value) {
                    multiplicities[*col_i][*row_i] += 1;
                } else {
                    panic!("Could not resolve a runtime table read");
                }
            }

            multiplicities
                .into_iter()
                .map(|v| v.into_iter().map(|x| F::from(x)).collect())
                .collect()
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
    > WitnessBuilderEnv<F, CIx, N_WIT, N_REL, N_DSEL, N_FSEL, LT>
{
    /// Create a new empty-state witness builder.
    pub fn create() -> Self {
        let mut lookups_row = BTreeMap::new();
        let mut lookup_multiplicities = BTreeMap::new();
        let mut runtime_lookups = BTreeMap::new();
        let mut runtime_tables = BTreeMap::new();
        let fixed_selectors = vec![vec![]; N_FSEL];
        for table_id in LT::all_variants().into_iter() {
            lookups_row.insert(table_id, Vec::new());
            lookup_multiplicities.insert(table_id, vec![0u64; table_id.length()]);
            if !table_id.is_fixed() {
                runtime_lookups.insert(table_id, vec![]);
                runtime_tables.insert(table_id, vec![]);
            }
        }

        Self {
            witness: vec![Witness {
                cols: Box::new([F::zero(); N_WIT]),
            }],

            lookup_multiplicities,
            lookup_reads: vec![lookups_row],
            runtime_lookups,
            runtime_tables,
            fixed_selectors,
            phantom_cix: PhantomData,
            assert_mapper: Box::new(|x| x),
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

    /// Return all runtime tables collected so far, padded to the domain size.
    pub fn get_runtime_tables(&self, domain_size: usize) -> BTreeMap<LT, Vec<Vec<Vec<F>>>> {
        let mut runtime_tables: BTreeMap<_, _> = self.runtime_tables.clone();
        for (_table_id, content) in runtime_tables.iter_mut() {
            // We pad the runtime table with dummies if it's too small.
            if content.len() < domain_size {
                let dummy_value = content[0].clone(); // we assume runtime tables are never empty
                content.append(&mut vec![dummy_value; domain_size - content.len()]);
            }
        }
        runtime_tables
    }

    pub fn get_logup_witness(
        &self,
        domain_size: usize,
        lookup_tables_data: BTreeMap<LT, Vec<Vec<Vec<F>>>>,
    ) -> BTreeMap<LT, LogupWitness<F, LT>> {
        // Building lookup values
        let mut lookup_tables: BTreeMap<LT, Vec<Vec<Logup<F, LT>>>> = BTreeMap::new();
        if !lookup_tables_data.is_empty() {
            for table_id in LT::all_variants().into_iter() {
                // Find how many lookups are done per table.
                let number_of_lookup_reads = self.lookup_reads[0].get(&table_id).unwrap().len();

                // Technically the number of lookups must be the same per
                // row, but let's check if it's actually so.
                for (i, lookup_row) in self.lookup_reads.iter().enumerate().take(domain_size) {
                    let number_of_lookups_currow = lookup_row.get(&table_id).unwrap().len();
                    assert!(
                        number_of_lookup_reads == number_of_lookups_currow,
                        "Different number of lookups in row {i:?} and row 0: {number_of_lookups_currow:?} vs {number_of_lookup_reads:?}"
                    );
                }
                let number_of_lookup_writes =
                    if table_id.is_fixed() || table_id.runtime_create_column() {
                        1
                    } else {
                        self.runtime_tables[&table_id].len()
                    };
                // +1 for the fixed table
                lookup_tables.insert(
                    table_id,
                    vec![vec![]; number_of_lookup_reads + number_of_lookup_writes],
                );
            }
        } else {
            debug!("No lookup tables data provided. Skipping lookup tables.");
        }

        for lookup_row in self.lookup_reads.iter().take(domain_size) {
            for (table_id, table) in lookup_tables.iter_mut() {
                for (j, lookup) in lookup_row.get(table_id).unwrap().iter().enumerate() {
                    table[j].push(lookup.clone())
                }
            }
        }

        let mut lookup_multiplicities: BTreeMap<LT, Vec<Vec<F>>> = BTreeMap::new();

        // Counting multiplicities & adding fixed column into the last column of every table.
        for (table_id, table) in lookup_tables.iter_mut() {
            let lookup_m: Vec<Vec<F>> = self.get_lookup_multiplicities(domain_size, *table_id);
            lookup_multiplicities.insert(*table_id, lookup_m.clone());

            if table_id.is_fixed() || table_id.runtime_create_column() {
                assert!(lookup_m.len() == 1);
                assert!(lookup_tables_data[table_id].len() == 1);
                let lookup_t = lookup_tables_data[table_id][0]
                    .iter()
                    .enumerate()
                    .map(|(i, v)| Logup {
                        table_id: *table_id,
                        numerator: -lookup_m[0][i],
                        value: v.clone(),
                    })
                    .collect();
                *(table.last_mut().unwrap()) = lookup_t;
            } else {
                // Add multiplicity vectors for runtime tables.
                for (col_i, lookup_column) in lookup_tables_data[table_id].iter().enumerate() {
                    let lookup_t = lookup_column
                        .iter()
                        .enumerate()
                        .map(|(i, v)| Logup {
                            table_id: *table_id,
                            numerator: -lookup_m[col_i][i],
                            value: v.clone(),
                        })
                        .collect();

                    let pos = table.len() - self.runtime_tables[table_id].len() + col_i;

                    (*table)[pos] = lookup_t;
                }
            }
        }

        for (table_id, m) in lookup_multiplicities.iter() {
            if !table_id.is_fixed() {
                // Temporary assertion; to be removed when we support bigger
                // runtime table/RAMlookups functionality.
                assert!(m.len() <= domain_size,
                        "We do not _yet_ support wrapping runtime tables that are bigger than domain size.");
            }
        }

        lookup_tables
            .iter()
            .filter_map(|(table_id, table)| {
                // Only add a table if it's used. Otherwise lookups fail.
                if !table.is_empty() && !table[0].is_empty() {
                    Some((
                        *table_id,
                        LogupWitness {
                            f: table.clone(),
                            m: lookup_multiplicities[table_id].clone(),
                        },
                    ))
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
        lookup_tables_data: BTreeMap<LT, Vec<Vec<Vec<F>>>>,
    ) -> ProofInputs<N_WIT, F, LT> {
        let evaluations = self.get_relation_witness(domain_size);
        let logups = self.get_logup_witness(domain_size, lookup_tables_data);

        ProofInputs {
            evaluations,
            logups,
        }
    }
}
