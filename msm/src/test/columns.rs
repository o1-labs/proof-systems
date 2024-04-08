use crate::{
    columns::{Column, ColumnIndexer},
    N_LIMBS,
};

/// Number of columns in the test circuits.
pub const TEST_N_COLUMNS: usize = 4 * N_LIMBS;

#[derive(Clone, Copy, Debug, PartialEq)]
/// Column indexer for MSM columns.
///
/// Columns A to D are used for testing right now, they are used for
/// either of the two equations:
///   A + B - C = 0
///   A * B - D = 0
pub enum TestColumnIndexer {
    A(usize),
    B(usize),
    C(usize),
    D(usize),
}

impl ColumnIndexer for TestColumnIndexer {
    fn to_column(self) -> Column {
        let to_column_inner = |offset, i| {
            assert!(i < N_LIMBS);
            Column::X(N_LIMBS * offset + i)
        };
        match self {
            TestColumnIndexer::A(i) => to_column_inner(0, i),
            TestColumnIndexer::B(i) => to_column_inner(1, i),
            TestColumnIndexer::C(i) => to_column_inner(2, i),
            TestColumnIndexer::D(i) => to_column_inner(3, i),
        }
    }
}
