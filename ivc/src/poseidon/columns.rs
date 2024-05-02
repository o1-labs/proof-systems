/// The column layout will be as follow, supposing a state size of 3 elements:
/// | C1 | C2 | C3 | C4  | C5  | C6  | ... | C_(k) | C_(k + 1) | C_(k + 2) |
/// |--- |----|----|-----|-----|-----|-----|-------|-----------|-----------|
/// |  x |  y | z  | x'  |  y' |  z' | ... |  x''  |     y''   |    z''    |
///                | MDS \circ SBOX  |     |        MDS \circ SBOX         |
///                |-----------------|     |-------------------------------|
/// where (x', y', z') = MDS(x^7, y^7, z^7), i.e. the result of the linear layer
/// We will have, for N full rounds:
/// - `3` input columns
/// - `N * 3` round columns, indexed by the round number and the index in the state,
/// the number of rounds.
/// The round constants are also added as columns.
// IMPROVEME: should be split the SBOX and the MDS?
// IMPROVEME: round constants should be public
// IMPROVEME: round constants should be part of the expression framework. The
// expression must be changed to support this.
use kimchi_msm::columns::{Column, ColumnIndexer};

#[derive(Debug, Clone, PartialEq)]
pub enum PoseidonColumn<const STATE_SIZE: usize, const NB_FULL_ROUND: usize> {
    Input(usize),
    Round(usize, usize),
    RoundConstant(usize, usize),
}

impl<const STATE_SIZE: usize, const NB_FULL_ROUND: usize> ColumnIndexer
    for PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>
{
    const COL_N: usize = STATE_SIZE + 2 * NB_FULL_ROUND * STATE_SIZE;

    fn to_column(self) -> Column {
        match self {
            PoseidonColumn::Input(i) => {
                assert!(i < STATE_SIZE);
                Column::Relation(i)
            }
            PoseidonColumn::Round(round, state_index) => {
                assert!(state_index < STATE_SIZE);
                // We start round 0
                assert!(round < NB_FULL_ROUND);
                let idx = STATE_SIZE + (round * STATE_SIZE + state_index);
                Column::Relation(idx)
            }
            PoseidonColumn::RoundConstant(round, state_index) => {
                assert!(state_index < STATE_SIZE);
                // We start round 0
                assert!(round < NB_FULL_ROUND);
                let offset = STATE_SIZE + STATE_SIZE * NB_FULL_ROUND;
                let idx = offset + (round * STATE_SIZE + state_index);
                Column::Relation(idx)
            }
        }
    }
}
