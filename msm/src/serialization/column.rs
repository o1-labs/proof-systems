use crate::{
    columns::{Column, ColumnIndexer},
    serialization::N_INTERMEDIATE_LIMBS,
    N_LIMBS,
};

/// Total number of columns in the serialization circuit
pub const SER_N_COLUMNS: usize = 6 * N_LIMBS + N_INTERMEDIATE_LIMBS + 9;

/// Columns used by the serialization subcircuit.
pub enum SerializationColumn {
    /// 3 88-bit inputs. For the row #i this represents the IPA challenge xi_{log(i)}.
    ChalKimchi(usize),
    /// N_INTERMEDIATE_LIMBS intermediate values, 4 bits long. Represent parts of the IPA challenge.
    ChalIntermediate(usize),
    /// N_LIMBS values, representing the converted IPA challenge.
    ChalConverted(usize),
    /// Previous coefficient C_j, this one is looked up. For the row i, the expected
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
    fn to_column(self) -> Column {
        match self {
            Self::ChalKimchi(j) => {
                assert!(j < 3);
                Column::X(j)
            }
            Self::ChalIntermediate(j) => {
                assert!(j < N_INTERMEDIATE_LIMBS);
                Column::X(3 + j)
            }
            Self::ChalConverted(j) => {
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
                Column::X(N_INTERMEDIATE_LIMBS + 5 * N_LIMBS + 9 + j)
            }
        }
    }
}
