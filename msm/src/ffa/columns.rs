use crate::columns::Column;
use crate::columns::ColumnIndexer;

use crate::N_LIMBS;

/// Number of columns in the FFA circuits.
pub const FFA_N_COLUMNS: usize = 9 * N_LIMBS;

#[derive(Clone, Copy, Debug, PartialEq)]
/// Column indexer for MSM columns.
///
/// Columns A to D are used for testing right now and will be removed.
///
/// Other columns represent the equation
///   `InputA(i) + InputB(i) = ModulusF(i) * Quotient + Carry(i) * 2^LIMB_SIZE - Carry(i-1)`
pub enum FFAColumnIndexer {
    A(usize),
    B(usize),
    C(usize),
    D(usize),
    InputA(usize),
    InputB(usize),
    ModulusF(usize),
    Remainder(usize),
    Carry(usize),
    Quotient,
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
            FFAColumnIndexer::InputA(i) => to_column_inner(4, i),
            FFAColumnIndexer::InputB(i) => to_column_inner(5, i),
            FFAColumnIndexer::ModulusF(i) => to_column_inner(6, i),
            FFAColumnIndexer::Remainder(i) => to_column_inner(7, i),
            FFAColumnIndexer::Carry(i) => {
                assert!(i < N_LIMBS - 1);
                to_column_inner(8, i)
            }
            FFAColumnIndexer::Quotient => to_column_inner(8, N_LIMBS - 1),
        }
    }
}

impl FFAColumnIndexer {
    pub fn column_to_ix(col: Column) -> Self {
        let Column::X(pos) = col;
        let upper_bound = |i: usize| (i + 1) * N_LIMBS;
        let pos_map = |i: usize| pos - upper_bound(i - 1);
        if pos < upper_bound(0) {
            FFAColumnIndexer::A(pos_map(0))
        } else if pos < upper_bound(1) {
            FFAColumnIndexer::B(pos_map(1))
        } else if pos < upper_bound(2) {
            FFAColumnIndexer::C(pos_map(2))
        } else if pos < upper_bound(3) {
            FFAColumnIndexer::D(pos_map(3))
        } else {
            panic!("column_to_ix: Invalid column index")
        }
    }
}
