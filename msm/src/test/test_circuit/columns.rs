use crate::{
    columns::{Column, ColumnIndexer},
    N_LIMBS,
};

/// Number of columns in the test circuits, including fixed selectors.
pub const N_COL_TEST: usize = 4 * N_LIMBS + N_FSEL_TEST;

/// Number of fixed selectors in the test circuit.
pub const N_FSEL_TEST: usize = 3;

/// Test column indexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestColumn {
    A(usize),
    B(usize),
    C(usize),
    D(usize),
    FixedSel1,
    FixedSel2,
    FixedSel3,
}

impl ColumnIndexer<usize> for TestColumn {
    const N_COL: usize = N_COL_TEST;
    fn to_column(self) -> Column<usize> {
        let to_column_inner = |offset, i| {
            assert!(i < N_LIMBS);
            Column::Relation(N_LIMBS * offset + i)
        };
        match self {
            TestColumn::A(i) => to_column_inner(0, i),
            TestColumn::B(i) => to_column_inner(1, i),
            TestColumn::C(i) => to_column_inner(2, i),
            TestColumn::D(i) => to_column_inner(3, i),
            TestColumn::FixedSel1 => Column::FixedSelector(0),
            TestColumn::FixedSel2 => Column::FixedSelector(1),
            TestColumn::FixedSel3 => Column::FixedSelector(2),
        }
    }
}
