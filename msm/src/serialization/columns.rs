use crate::columns::Column;
use crate::columns::ColumnIndexer;
use crate::LIMBS_NUM;

/// Columns for the circuit splitting the bulletproof challenges in limbs used
/// by the MSM.
pub enum DecompositionColumnIndexer {
    KimchiLimbs(usize),
    MSMLimbs(usize),
    IntermediateKimchiLimbs(usize),
}

impl ColumnIndexer for DecompositionColumnIndexer {
    fn ix_to_column(self) -> Column {
        match self {
            DecompositionColumnIndexer::KimchiLimbs(i) => {
                assert!(i < 3);
                Column::X(i)
            }
            DecompositionColumnIndexer::MSMLimbs(i) => {
                assert!(i < LIMBS_NUM);
                Column::X(3 + i)
            }
            DecompositionColumnIndexer::IntermediateKimchiLimbs(i) => {
                assert!(i < 3 + LIMBS_NUM);
                Column::X(3 + LIMBS_NUM + i)
            }
        }
    }
}
