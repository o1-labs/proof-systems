use crate::{
    columns::{Column, ColumnIndexer},
    N_LIMBS,
};

/// Number of columns in the test circuits.
pub const TEST_N_COLUMNS: usize = 4 * N_LIMBS + 1;

/// Column indexer for MSM columns.
///
/// Columns A to D are used for testing right now, they are used for
/// either of the two equations:
///   A + B - C = 0
///   A * B - D = 0
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestColumn {
    A(usize),
    B(usize),
    C(usize),
    D(usize),
    FixedE,
}

impl ColumnIndexer for TestColumn {
    const N_COL: usize = TEST_N_COLUMNS;
    fn to_column(self) -> Column {
        let to_column_inner = |offset, i| {
            assert!(i < N_LIMBS);
            Column::Relation(N_LIMBS * offset + i)
        };
        match self {
            TestColumn::A(i) => to_column_inner(0, i),
            TestColumn::B(i) => to_column_inner(1, i),
            TestColumn::C(i) => to_column_inner(2, i),
            TestColumn::D(i) => to_column_inner(3, i),
            TestColumn::FixedE => Column::FixedSelector(0),
        }
    }
}
