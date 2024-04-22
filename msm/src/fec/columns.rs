use crate::{
    columns::{Column, ColumnIndexer},
    N_LIMBS,
};

/// Number of columns in the FEC circuits.
pub const FEC_N_COLUMNS: usize = 12 * N_LIMBS + 29;

/// Columns used by the serialization subcircuit.
pub struct FECColumn(pub usize);

impl ColumnIndexer for FECColumn {
    const COL_N: usize = FEC_N_COLUMNS;
    fn to_column(self) -> Column {
        match self {
            FECColumn(j) => Column::X(j),
        }
    }
}
