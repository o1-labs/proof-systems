use crate::columns::Column;
use crate::columns::ColumnIndexer;

use crate::N_LIMBS;

/// Number of columns in the FFA circuits.
pub const FFA_N_COLUMNS: usize = 4 * N_LIMBS;

#[derive(Clone, Copy, Debug, PartialEq)]
/// Column indexer for MSM columns
pub enum FFAColumnIndexer {
    A(usize),
    B(usize),
    C(usize),
    D(usize),
}

impl ColumnIndexer for FFAColumnIndexer {
    fn ix_to_column(self) -> Column {
        let to_column_inner = |offset, i| {
            assert!(i < N_LIMBS);
            Column::X(N_LIMBS * offset + i)
        };
        match self {
            FFAColumnIndexer::A(i) => to_column_inner(0, i),
            FFAColumnIndexer::B(i) => to_column_inner(1, i),
            FFAColumnIndexer::C(i) => to_column_inner(2, i),
            FFAColumnIndexer::D(i) => to_column_inner(3, i),
        }
    }
}
