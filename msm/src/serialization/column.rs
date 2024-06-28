use crate::{
    columns::{Column, ColumnIndexer},
    serialization::N_INTERMEDIATE_LIMBS,
    N_LIMBS,
};

/// Total number of columns in the serialization circuit, including fixed selectors.
pub const N_COL_SER: usize = 6 * N_LIMBS + N_INTERMEDIATE_LIMBS + 9 + N_FSEL_SER;

/// Number of fixed selectors for serialization circuit.
pub const N_FSEL_SER: usize = 2;

/// Columns used by the serialization subcircuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SerializationColumn {
    /// A fixed selector column that gives one the current row, starting with 0.
    CurrentRow,
    /// For current row i, this is i - 2^{ceil(log(i)) - 1}
    PreviousCoeffRow,
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
    /// The resulting coefficient C_i = C_{i - 2^{ceil(log i) - 1}} * xi_{log(i)}. In small limbs.
    CoeffResult(usize),
}

impl ColumnIndexer for SerializationColumn {
    const N_COL: usize = N_COL_SER;
    fn to_column(self) -> Column {
        match self {
            Self::CurrentRow => Column::FixedSelector(0),
            Self::PreviousCoeffRow => Column::FixedSelector(1),
            Self::ChalKimchi(j) => {
                assert!(j < 3);
                Column::Relation(j)
            }
            Self::ChalIntermediate(j) => {
                assert!(j < N_INTERMEDIATE_LIMBS);
                Column::Relation(3 + j)
            }
            Self::ChalConverted(j) => {
                assert!(j < N_LIMBS);
                Column::Relation(N_INTERMEDIATE_LIMBS + 3 + j)
            }
            Self::CoeffInput(j) => {
                assert!(j < N_LIMBS);
                Column::Relation(N_INTERMEDIATE_LIMBS + N_LIMBS + 3 + j)
            }
            Self::FFieldModulus(j) => {
                assert!(j < 4);
                Column::Relation(N_INTERMEDIATE_LIMBS + 2 * N_LIMBS + 3 + j)
            }
            Self::Quotient(j) => {
                assert!(j < N_LIMBS);
                Column::Relation(N_INTERMEDIATE_LIMBS + 2 * N_LIMBS + 7 + j)
            }
            Self::Carry(j) => {
                assert!(j < 2 * N_LIMBS + 2);
                Column::Relation(N_INTERMEDIATE_LIMBS + 3 * N_LIMBS + 7 + j)
            }
            Self::CoeffResult(j) => {
                assert!(j < N_LIMBS);
                Column::Relation(N_INTERMEDIATE_LIMBS + 5 * N_LIMBS + 9 + j)
            }
        }
    }
}
