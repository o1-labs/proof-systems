use crate::LIMBS_NUM;

// @volhovm: maybe this needs to be a trait
/// Describe a generic indexed variable X_{i}.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Column {
    X(usize),
}

/// A datatype expressing a generalized column, but with potentially
/// more convenient interface than a bare column.
pub trait ColumnIndexer {
    fn ix_to_column(self) -> Column;
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// Column indexer for MSM columns
pub enum MSMColumnIndexer {
    A(usize),
    B(usize),
    C(usize),
}

impl ColumnIndexer for MSMColumnIndexer {
    fn ix_to_column(self) -> Column {
        let to_column_inner = |offset, i| {
            assert!(i < LIMBS_NUM);
            Column::X(LIMBS_NUM * offset + i)
        };
        match self {
            MSMColumnIndexer::A(i) => to_column_inner(0, i),
            MSMColumnIndexer::B(i) => to_column_inner(1, i),
            MSMColumnIndexer::C(i) => to_column_inner(2, i),
        }
    }
}
