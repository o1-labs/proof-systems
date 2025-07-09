use ark_ff::{FftField, One, Zero};
use poly_commitment::PolyComm;
use serde::{Deserialize, Serialize};

pub mod range_check;
pub mod xor;

// If you add new tables, update ../../../../../book/src/kimchi/lookup.md
// accordingly

//~ spec:startcode
/// The table ID associated with the XOR lookup table.
pub const XOR_TABLE_ID: i32 = 0;

/// The range check table ID.
pub const RANGE_CHECK_TABLE_ID: i32 = 1;
//~ spec:endcode

/// Enumerates the different 'fixed' lookup tables used by individual gates
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateLookupTable {
    Xor,
    RangeCheck,
}

/// Enumerates the different 'fixed' lookup tables used by individual gates
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GateLookupTables {
    pub xor: bool,
    pub range_check: bool,
}

impl core::ops::Index<GateLookupTable> for GateLookupTables {
    type Output = bool;

    fn index(&self, index: GateLookupTable) -> &Self::Output {
        match index {
            GateLookupTable::Xor => &self.xor,
            GateLookupTable::RangeCheck => &self.range_check,
        }
    }
}

impl core::ops::IndexMut<GateLookupTable> for GateLookupTables {
    fn index_mut(&mut self, index: GateLookupTable) -> &mut Self::Output {
        match index {
            GateLookupTable::Xor => &mut self.xor,
            GateLookupTable::RangeCheck => &mut self.range_check,
        }
    }
}

impl IntoIterator for GateLookupTables {
    type Item = GateLookupTable;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        // Destructor pattern to make sure we add new lookup patterns.
        let GateLookupTables { xor, range_check } = self;

        let mut patterns = Vec::with_capacity(2);

        if xor {
            patterns.push(GateLookupTable::Xor)
        }
        if range_check {
            patterns.push(GateLookupTable::RangeCheck)
        }
        patterns.into_iter()
    }
}

/// A table of values that can be used for a lookup, along with the ID for the table.
#[derive(Debug, Clone)]
pub struct LookupTable<F> {
    pub id: i32,
    pub data: Vec<Vec<F>>,
}

impl<F> LookupTable<F>
where
    F: FftField,
{
    /// Return true if the table has an entry (row) containing all zeros.
    pub fn has_zero_entry(&self) -> bool {
        // reminder: a table is written as a list of columns,
        // not as a list of row entries.
        for row in 0..self.len() {
            if self.data.iter().all(|col| col[row].is_zero()) {
                return true;
            }
        }
        false
    }

    /// Returns the number of columns, i.e. the width of the table.
    /// It is less error prone to introduce this method than using the public
    /// field data.
    pub fn width(&self) -> usize {
        self.data.len()
    }

    /// Returns the length of the table.
    pub fn len(&self) -> usize {
        self.data[0].len()
    }

    /// Returns `true` if the lookup table is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Returns the lookup table associated to a [`GateLookupTable`].
pub fn get_table<F: FftField>(table_name: GateLookupTable) -> LookupTable<F> {
    match table_name {
        GateLookupTable::Xor => xor::xor_table(),
        GateLookupTable::RangeCheck => range_check::range_check_table(),
    }
}

impl GateLookupTable {
    /// Returns the lookup table associated to a [`GateLookupTable`].
    pub fn table_size(&self) -> usize {
        match self {
            GateLookupTable::Xor => xor::TABLE_SIZE,
            GateLookupTable::RangeCheck => range_check::TABLE_SIZE,
        }
    }
}

/// Let's say we want to do a lookup in a "vector-valued" table `T: Vec<[F; n]>` (here I
/// am using `[F; n]` to model a vector of length `n`).
///
/// For `i < n`, define `T_i := T.map(|t| t[i]).collect()`. In other words, the table
/// obtained by taking the `ith` entry of each element of `T`.
///
/// In the lookup argument, we perform lookups in `T` by sampling a random challenge
/// `joint_combiner`, and computing a "combined" lookup table `sum_{i < n} joint_combiner^i T_i`.
///
/// To check a vector's membership in this lookup table, we combine the values in that vector
/// analogously using `joint_combiner`.
///
/// This function computes that combined value.
pub fn combine_table_entry<'a, F, I>(
    joint_combiner: &F,
    table_id_combiner: &F,
    v: I,
    // TODO: this should be an option?
    table_id: &F,
) -> F
where
    F: 'a, // Any references in `F` must have a lifetime longer than `'a`.
    F: Zero + One + Clone,
    I: DoubleEndedIterator<Item = &'a F>,
{
    v.rev()
        .fold(F::zero(), |acc, x| joint_combiner.clone() * acc + x.clone())
        + table_id_combiner.clone() * table_id.clone()
}

/// Same as [`combine_table_entry`], but for an entire table.
/// The function will panic if given an empty table (0 columns).
///
/// # Panics
///
/// Will panic if `columns` is empty.
pub fn combine_table<G>(
    columns: &[&PolyComm<G>],
    column_combiner: G::ScalarField,
    table_id_combiner: G::ScalarField,
    table_id_vector: Option<&PolyComm<G>>,
    runtime_vector: Option<&PolyComm<G>>,
) -> PolyComm<G>
where
    G: poly_commitment::commitment::CommitmentCurve,
{
    assert!(!columns.is_empty());

    // combine the columns
    let mut j = G::ScalarField::one();
    let mut scalars = vec![j];
    let mut commitments = vec![columns[0]];
    for comm in columns.iter().skip(1) {
        j *= column_combiner;
        scalars.push(j);
        commitments.push(comm);
    }

    // combine the table id
    if let Some(table_id) = table_id_vector {
        scalars.push(table_id_combiner);
        commitments.push(table_id);
    }

    // combine the runtime vector
    if let Some(runtime) = runtime_vector {
        scalars.push(column_combiner); // 2nd column idx is j^1
        commitments.push(runtime);
    }

    PolyComm::multi_scalar_mul(&commitments, &scalars)
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use ark_ff::PrimeField;
    use ocaml;
    use ocaml_gen;

    use super::LookupTable;

    //
    // CamlLookupTable<CamlF>
    //

    #[derive(ocaml::ToValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlLookupTable<CamlF> {
        pub id: i32,
        pub data: Vec<Vec<CamlF>>,
    }

    impl<F, CamlF> From<CamlLookupTable<CamlF>> for LookupTable<F>
    where
        F: PrimeField,
        CamlF: Into<F>,
    {
        fn from(caml_lt: CamlLookupTable<CamlF>) -> Self {
            Self {
                id: caml_lt.id,
                data: caml_lt
                    .data
                    .into_iter()
                    .map(|t| t.into_iter().map(Into::into).collect())
                    .collect(),
            }
        }
    }

    impl<F, CamlF> From<LookupTable<F>> for CamlLookupTable<CamlF>
    where
        F: PrimeField,
        CamlF: From<F>,
    {
        fn from(lt: LookupTable<F>) -> Self {
            Self {
                id: lt.id,
                data: lt
                    .data
                    .into_iter()
                    .map(|t| t.into_iter().map(Into::into).collect())
                    .collect(),
            }
        }
    }
}
