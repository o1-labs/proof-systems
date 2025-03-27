/// The column layout will be as follow, supposing a state size of 3 elements:
/// ```text
/// | C1 | C2 | C3 | C4  | C5  | C6  | ... | C_(k) | C_(k + 1) | C_(k + 2) |
/// |--- |----|----|-----|-----|-----|-----|-------|-----------|-----------|
/// |  x |  y | z  | x'  |  y' |  z' | ... |  x''  |     y''   |    z''    |
///                | MDS \circ SBOX  |     |        MDS \circ SBOX         |
///                |-----------------|     |-------------------------------|
///                   Divided in 4
///                 blocks of degree 2
///                   constraints
/// ```
///
/// where (x', y', z') = MDS(x^5, y^5, z^5), i.e. the result of the linear
/// layer.
use kimchi_msm::columns::{Column, ColumnIndexer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PoseidonColumn<
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    const NB_PARTIAL_ROUND: usize,
> {
    Input(usize),
    // we use the constraint:
    // y = x * x  -> x^2 -> i
    // y' = y * y -> x^4 -> i + 1
    // y'' = y * y' -> x^5 -> i + 2
    // y'' * MDS -> i + 4
    // --> nb round, 4 * state_size
    FullRound(usize, usize),
    // round, idx (4 + STATE_SIZE - 1)
    PartialRound(usize, usize),
    RoundConstant(usize, usize),
}

impl<const STATE_SIZE: usize, const NB_FULL_ROUND: usize, const NB_PARTIAL_ROUND: usize>
    ColumnIndexer<usize> for PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>
{
    // - STATE_SIZE input columns
    // - for each partial round:
    //   - 1 column for x^2 -> x * x
    //   - 1 column for x^4 -> x^2 * x^2
    //   - 1 column for x^5 -> x^4 * x
    //   - 1 column for x^5 * MDS(., L)
    //   - STATE_SIZE - 1 columns for the unchanged elements multiplied by the
    //   MDS + rc
    // - for each full round:
    //   - STATE_SIZE state columns for x^2 -> x * x
    //   - STATE_SIZE state columns for x^4 -> x^2 * x^2
    //   - STATE_SIZE state columns for x^5 -> x^4 * x
    //   - STATE_SIZE state columns for x^5 * MDS(., L)
    // For the round constants, we have:
    // - STATE_SIZE * (NB_PARTIAL_ROUND + NB_FULL_ROUND)
    const N_COL: usize =
        // input
        STATE_SIZE
            + 4 * NB_FULL_ROUND * STATE_SIZE // full round
            + (4 + STATE_SIZE - 1) * NB_PARTIAL_ROUND // partial round
            + STATE_SIZE * (NB_PARTIAL_ROUND + NB_FULL_ROUND); // fixed selectors

    fn to_column(self) -> Column<usize> {
        // number of reductions for
        // x -> x^2 -> x^4 -> x^5 -> x^5 * MDS
        let nb_red = 4;
        match self {
            PoseidonColumn::Input(i) => {
                assert!(i < STATE_SIZE);
                Column::Relation(i)
            }
            PoseidonColumn::PartialRound(round, idx) => {
                assert!(round < NB_PARTIAL_ROUND);
                assert!(idx < nb_red + STATE_SIZE - 1);
                let offset = STATE_SIZE;
                let idx = offset + round * (nb_red + STATE_SIZE - 1) + idx;
                Column::Relation(idx)
            }
            PoseidonColumn::FullRound(round, state_index) => {
                assert!(state_index < nb_red * STATE_SIZE);
                // We start round 0
                assert!(round < NB_FULL_ROUND);
                let offset = STATE_SIZE + (NB_PARTIAL_ROUND * (nb_red + STATE_SIZE - 1));
                let idx = offset + (round * nb_red * STATE_SIZE + state_index);
                Column::Relation(idx)
            }
            PoseidonColumn::RoundConstant(round, state_index) => {
                assert!(state_index < STATE_SIZE);
                assert!(round < NB_FULL_ROUND + NB_PARTIAL_ROUND);
                let idx = round * STATE_SIZE + state_index;
                Column::FixedSelector(idx)
            }
        }
    }
}
