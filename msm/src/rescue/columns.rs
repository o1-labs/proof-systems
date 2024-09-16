/// The column layout will be as followed, optimised to compute a whole
/// permutation on one row, supposing a state of 3 elements:
/// | C1 | C2 | C3 |   C4   |   C5  |  C6  |   C7   |   C8  |  C9      | ... | C(n-2) | C(n-1) | Cn |
/// |--- |----|----|--------|-------|------|--------|-------|----------|-----|--------|--------|----|
/// |  x |  y | z  |   x'   |  y'   |  z'  |   x'   |  y'   |  z'      | ... |  o1    |  o2    | o3 |
///                | MDS \circ SBOX_alpha  | MDS \circ SBOX_alpha_inv  |
///                |-----------------------|---------------------------|
///                 \                                                 /
///                  \_________________ 1 round _____________________/
///                   ---> Repeated NB_ROUND times on the same row <---
///                                (depending on the security)
use crate::columns::{Column, ColumnIndexer};

#[derive(Debug, Clone, Copy)]
pub enum RescueColumn<const STATE_SIZE: usize, const NB_ROUND: usize> {
    // The index is the index of the state element
    Input(usize),
    // First index is the round, second is the index of the state element
    RoundConstant(usize, usize),
    // First index is the round, second is the index of the state element
    Round(usize, usize),
}

impl<const STATE_SIZE: usize, const NB_ROUND: usize> ColumnIndexer
    for RescueColumn<STATE_SIZE, NB_ROUND>
{
    //                    INPUT              ROUND CONSTANT                 ROUND
    const COL_N: usize = STATE_SIZE + (2 * STATE_SIZE * NB_ROUND) + (2 * STATE_SIZE * NB_ROUND);

    fn to_column(self) -> Column {
        match self {
            RescueColumn::Input(i) => {
                assert!(i < STATE_SIZE);
                Column::X(i)
            }
            RescueColumn::RoundConstant(i, j) => {
                assert!(i < NB_ROUND);
                // twice because we apply sbox_alpha and sbox_alpha_inv in one
                // round
                assert!(j < 2 * STATE_SIZE);
                let offset = STATE_SIZE;
                let pos = offset + i * (2 * STATE_SIZE) + j;
                Column::X(pos)
            }
            RescueColumn::Round(i, j) => {
                assert!(i < NB_ROUND);
                // twice because we apply sbox_alpha and sbox_alpha_inv in one
                assert!(j < STATE_SIZE * 2);
                let offset = STATE_SIZE + NB_ROUND * (2 * STATE_SIZE);
                let pos = offset + i * (2 * STATE_SIZE) + j;
                Column::X(pos)
            }
        }
    }
}
