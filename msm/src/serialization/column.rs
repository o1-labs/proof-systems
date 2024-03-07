use crate::columns::{Column, ColumnIndexer};
use crate::serialization::N_INTERMEDIATE_LIMBS;
use crate::N_LIMBS;

pub enum SerializationColumn {
    KimchiLimb(usize),
    MSMLimb(usize),
    IntermediateLimb(usize),
}

impl ColumnIndexer for SerializationColumn {
    fn ix_to_column(self) -> Column {
        match self {
            Self::KimchiLimb(j) => {
                assert!(j < 3);
                Column::X(j)
            }
            Self::MSMLimb(j) => {
                assert!(j < N_LIMBS);
                Column::X(j + 3)
            }
            Self::IntermediateLimb(j) => {
                assert!(j < N_INTERMEDIATE_LIMBS);
                Column::X(j + N_LIMBS + 3)
            }
        }
    }
}
