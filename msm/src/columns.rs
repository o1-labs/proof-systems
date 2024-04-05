/// Describe a generic indexed variable X_{i}.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Column {
    X(usize),
    // Columns related to the lookup protocol
    /// Partial sums, indexed. This corresponds to the `h_i`
    LookupPartialSum(usize),
    /// Multiplicities, indexed. This corresponds to the `m_i`
    LookupMultiplicity(u32),
    /// The lookup aggregation, i.e. `phi`
    LookupAggregation,
    /// The fixed tables. The parameter is considered to the indexed table.
    /// u32 has been arbitrarily chosen as it seems to be already large enough
    LookupFixedTable(u32),
}

/// A datatype expressing a generalized column, but with potentially
/// more convenient interface than a bare column.
pub trait ColumnIndexer {
    fn to_column(self) -> Column;
}
