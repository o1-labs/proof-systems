use crate::columns::{Column, ColumnIndexer};
use crate::serialization::N_INTERMEDIATE_LIMBS;
use crate::N_LIMBS;

/// Column used by the serialization subcircuit
/// It is not used yet.
pub enum SerializationColumn {
    /// 3 88 bits inputs
    KimchiLimb(usize),
    /// N_LIMBS values, representing the limbs used by the MSM
    MSMLimb(usize),
    /// N_INTERMEDIATE_LIMBS intermediate values, 4 bits long.
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
