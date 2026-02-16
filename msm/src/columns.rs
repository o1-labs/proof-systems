use std::collections::HashMap;

use kimchi::circuits::expr::{CacheId, FormattedOutput};

/// Describe a generic indexed variable X_{i}.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub enum Column<T> {
    /// Columns related to the relation encoded in the circuit
    Relation(T),
    /// Columns related to dynamic selectors to indicate gate type
    DynamicSelector(usize),
    /// Constant column that is /always/ fixed for a given circuit.
    FixedSelector(usize),
    // Columns related to the lookup protocol
    /// Partial sums. This corresponds to the `h_i`.
    /// It is first indexed by the table ID, and after that internal index.
    LookupPartialSum((u32, usize)),
    /// Multiplicities, indexed. This corresponds to the `m_i`. First
    /// indexed by table ID, then internal index.
    LookupMultiplicity((u32, usize)),
    /// The lookup aggregation, i.e. `phi`
    LookupAggregation,
    /// The fixed tables. The parameter is considered to the indexed table.
    LookupFixedTable(u32),
}

impl Column<usize> {
    /// Adds offset if the column is `Relation`. Fails otherwise.
    pub fn add_rel_offset(self, offset: usize) -> Column<usize> {
        let Column::Relation(i) = self else {
            todo!("add_rel_offset is only implemented for the relation columns")
        };
        Column::Relation(offset + i)
    }
}

impl FormattedOutput for Column<usize> {
    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Relation(i) => format!("x_{{{i}}}"),
            Column::FixedSelector(i) => format!("fs_{{{i}}}"),
            Column::DynamicSelector(i) => format!("ds_{{{i}}}"),
            Column::LookupPartialSum((table_id, i)) => format!("h_{{{table_id}, {i}}}"),
            Column::LookupMultiplicity((table_id, i)) => format!("m_{{{table_id}, {i}}}"),
            Column::LookupFixedTable(i) => format!("t_{{{i}}}"),
            Column::LookupAggregation => String::from("φ"),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Relation(i) => format!("x[{i}]"),
            Column::FixedSelector(i) => format!("fs[{i}]"),
            Column::DynamicSelector(i) => format!("ds[{i}]"),
            Column::LookupPartialSum((table_id, i)) => format!("h[{table_id}, {i}]"),
            Column::LookupMultiplicity((table_id, i)) => format!("m[{table_id}, {i}]"),
            Column::LookupFixedTable(i) => format!("t[{i}]"),
            Column::LookupAggregation => String::from("φ"),
        }
    }

    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        // FIXME
        unimplemented!("Not used at the moment")
    }

    fn is_alpha(&self) -> bool {
        // FIXME
        unimplemented!("Not used at the moment")
    }
}

/// A datatype expressing a generalized column, but with potentially
/// more convenient interface than a bare column.
pub trait ColumnIndexer<T>: core::fmt::Debug + Copy + Eq + Ord {
    /// Total number of columns in this index.
    const N_COL: usize;

    /// Flatten the column "alias" into the integer-like column.
    fn to_column(self) -> Column<T>;
}
