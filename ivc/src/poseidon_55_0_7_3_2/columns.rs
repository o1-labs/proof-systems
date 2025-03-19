/// The column layout will be as follow, supposing a state size of 3 elements:
///
/// ```text
/// | C1 | C2 | C3 | C4  | C5  | C6  | ... | C_(k) | C_(k + 1) | C_(k + 2) |
/// |--- |----|----|-----|-----|-----|-----|-------|-----------|-----------|
/// |  x |  y | z  | x'  |  y' |  z' | ... |  x''  |     y''   |    z''    |
///                | MDS \circ SBOX  |     |        MDS \circ SBOX         |
///                |-----------------|     |-------------------------------|
///                   Divided in 5
///                 blocks of degree 2
///                   constraints
/// ```
///
/// where (x', y', z') = MDS(x^7, y^7, z^7), i.e. the result of the linear
/// layer.
///
/// We will have, for N full rounds:
/// - `3` input columns
/// - `5 N * 3` round columns, indexed by the round number and the index in the
///   state, the number of rounds.
use kimchi_msm::columns::{Column, ColumnIndexer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PoseidonColumn<const STATE_SIZE: usize, const NB_FULL_ROUND: usize> {
    Input(usize),
    // nb round, state
    // we use the constraint:
    // y = x * x  -> x^2 -> i
    // y' = y * y -> x^4 -> i + 1
    // y'' = y * y' -> x^6 -> i + 2
    // z = y'' * x -> i + 3
    // z * MDS -> i + 4
    // --> 5 * state, nb round
    Round(usize, usize),
    RoundConstant(usize, usize),
}

impl<const STATE_SIZE: usize, const NB_FULL_ROUND: usize> ColumnIndexer<usize>
    for PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>
{
    // - STATE_SIZE input columns
    // - for each round:
    //   - STATE_SIZE state columns for x^2 -> x * x
    //   - STATE_SIZE state columns for x^4 -> x^2 * x^2
    //   - STATE_SIZE state columns for x^6 -> x^4 * x^2
    //   - STATE_SIZE state columns for x^7 -> x^6 * x
    //   - STATE_SIZE state columns for x^7 * MDS(., L)
    // - STATE_SIZE * NB_FULL_ROUND constants
    const N_COL: usize = STATE_SIZE + 5 * NB_FULL_ROUND * STATE_SIZE;

    fn to_column(self) -> Column<usize> {
        match self {
            PoseidonColumn::Input(i) => {
                assert!(i < STATE_SIZE);
                Column::Relation(i)
            }
            PoseidonColumn::Round(round, state_index) => {
                assert!(state_index < 5 * STATE_SIZE);
                // We start round 0
                assert!(round < NB_FULL_ROUND);
                let idx = STATE_SIZE + (round * 5 * STATE_SIZE + state_index);
                Column::Relation(idx)
            }
            PoseidonColumn::RoundConstant(round, state_index) => {
                assert!(state_index < STATE_SIZE);
                // We start round 0
                assert!(round < NB_FULL_ROUND);
                let idx = round * STATE_SIZE + state_index;
                Column::FixedSelector(idx)
            }
        }
    }
}
