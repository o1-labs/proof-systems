use crate::columns::{Column, ColumnIndexer};
use crate::serialization::N_INTERMEDIATE_LIMBS;
use crate::N_LIMBS;

/// Total number of columns in the serialization circuit
pub const SER_N_COLUMNS: usize = 5 * N_LIMBS + N_INTERMEDIATE_LIMBS + 9;

/// Column used by the serialization subcircuit
/// It is not used yet.
pub enum SerializationColumn {
    /// 3 88 bits inputs. For the row #i this represents the IPA challenge xi_{log(i)}.
    KimchiLimb(usize),
    /// N_INTERMEDIATE_LIMBS intermediate values, 4 bits long.
    IntermediateLimb(usize),
    /// N_LIMBS values, representing the limbs used by the MSM
    MSMLimb(usize),
    /// Previous C_j, this one is looked up. For the row i, the expected
    /// value is (C_i >> 1).
    CoeffInput(usize),
    /// Trusted (for range) foreign field modulus, in 4 big limbs.
    FFieldModulus(usize),
    /// Quotient limbs
    Quotient(usize),
    /// Carry limbs
    Carry(usize),
    /// The resulting coefficient C_i = (C_i >> 1) * xi_{log(i)}. In small limbs.
    CoeffResult(usize),
}

impl ColumnIndexer for SerializationColumn {
    fn ix_to_column(self) -> Column {
        match self {
            Self::KimchiLimb(j) => {
                assert!(j < 3);
                Column::X(j)
            }
            Self::IntermediateLimb(j) => {
                assert!(j < N_INTERMEDIATE_LIMBS);
                Column::X(3 + j)
            }
            Self::MSMLimb(j) => {
                assert!(j < N_LIMBS);
                Column::X(N_INTERMEDIATE_LIMBS + 3 + j)
            }
            Self::CoeffInput(j) => {
                assert!(j < N_LIMBS);
                Column::X(N_INTERMEDIATE_LIMBS + N_LIMBS + 3 + j)
            }
            Self::FFieldModulus(j) => {
                assert!(j < 4);
                Column::X(N_INTERMEDIATE_LIMBS + 2 * N_LIMBS + 3 + j)
            }
            Self::Quotient(j) => {
                assert!(j < N_LIMBS);
                Column::X(N_INTERMEDIATE_LIMBS + 2 * N_LIMBS + 7 + j)
            }
            Self::Carry(j) => {
                assert!(j < 2 * N_LIMBS + 2);
                Column::X(N_INTERMEDIATE_LIMBS + 3 * N_LIMBS + 7 + j)
            }
            Self::CoeffResult(j) => {
                assert!(j < N_LIMBS);
                Column::X(N_INTERMEDIATE_LIMBS + 4 * N_LIMBS + 9 + j)
            }
        }
    }
}
