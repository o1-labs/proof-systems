use kimchi::circuits::expr::{Domain, GenericColumn};

/// Describe a generic indexed variable X_{i}.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Column {
    X(usize),
    // Columns related to the lookup protocol
    /// Partial sums, indexed. This corresponds to the `h_i`
    LookupPartialSum(usize),
    /// Multiplicities, indexed. This corresponds to the `m_i`
    LookupMultiplicity(u32),
    LookupAggregation,
}

impl GenericColumn for Column {
    fn column_domain(&self) -> Domain {
        // TODO FIXME check this is a tricky variable it should match the evalution in column
        // this must be bigger or equal than degree chosen in runtime inside evaluations() for
        // evaluating an expression = degree of expression that is evaluated
        // And also ... in some cases... bigger than the witness column size? Equal?
        Domain::D4
    }
}

/// A datatype expressing a generalized column, but with potentially
/// more convenient interface than a bare column.
pub trait ColumnIndexer {
    // TODO: rename it in to_column. It is not necessary to have ix_
    fn ix_to_column(self) -> Column;
}
