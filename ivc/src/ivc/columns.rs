use crate::{ivc::interpreter::N_LIMBS_XLARGE, poseidon::columns::PoseidonColumn};
use kimchi_msm::{
    circuit_design::composition::MPrism,
    columns::{Column, ColumnIndexer},
    fec::columns::FECColumn,
    serialization::interpreter::{N_LIMBS_LARGE, N_LIMBS_SMALL},
};

pub const IVC_POSEIDON_STATE_SIZE: usize = 3;
pub const IVC_POSEIDON_NB_FULL_ROUND: usize = 55;

pub type IVCPoseidonColumn = PoseidonColumn<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>;

/// The IVC circuit is tiled vertically. We assume we have as much
/// rows as we need: if we don't, we wrap around and continue.
///
/// The biggest blocks are hashes and ECAdds, so other blocks may be wider.
///
/// N := N_IVC + N_APP is the total number of columns in the circuit.
///
/// Vertically stacked blocks are as follows:
///
///```text
///
///              34            8      4
///            Input1         R75   R150
///  1   |-----------------|-------|----|
///      |      C_L1       |       |    |
///      |      C_L2       |       |    |
///      |                 |       |    |
///      |      ...        |       |    |
///   N  |-----------------|       |    |
///      |      C_R1       |       |    |
///      |                 |       |    |
///      |      ...        |       |    |
///  2N  |-----------------|       |    |
///      |      C_O1       |       |    |
///      |                 |       |    |
///      |      ...        |       |    |
///  3N  |-----------------|-------|----|
///      0       ...     34*2    76    80
///
///
///                      Hashes
///     (one hash at a row, passing data to the next one)
///     (for i∈N, the input row #i containing 4 150-bit elements
///      is processed by hash rows 2*i and 2*i+1)
///
///  1   |------------------------------------------|
///      |                                          |
///      |                                         .| . here is h_l
///  2N  |------------------------------------------|
///      |                                          |
///      |                                         .| . here is h_r
///  4N  |------------------------------------------|
///      |                                          |
///      |                                         .| . here is h_o
///  6N  |------------------------------------------|
///      |                                         .| r = h_lr = h(h_l,h_r)
///      |                                         .| ϕ = h_lro = h(r,h_o)
/// 6N+2 |------------------------------------------|
///
///     constϕ
///         constr
///                ϕ^i             ϕ^i        r*ϕ^i
///                      r*ϕ^i  in 17 limbs  in 17 limbs
///                               each        each
///   1  |---|---|-----|------|------------|------------|
///      | ϕ   r    ϕ     rϕ  |            |            |
///      | ϕ   r   ϕ^2   rϕ^2 |            |            |
///      | ϕ   r   ϕ^3   rϕ^3 |            |            |
///      |                    |            |            |
///      |                    |            |            |
///      |                    |            |            |
///  i   |                    |            |            |
///      |                    |            |            |
///      |                    |            |            |
///      |                    |            |            |
///      |                    |            |            |
///  N   |--------------------|------------|------------|
///       1    2   3   4 ...        4+17          4+2*17
///
///
///
///          FEC Additions, one per row, each one is ~230 columns
///
///          input#1    input#2          FEC ADD computation          output
///   1   |------------------------------------------------------|-------------|
///       |  C_{R'_i} | bucket[ϕ^i]_k   |      ϕ^i·C_{R'_i}      |  newbucket  |
///       |           |                 |                        |             |
///       |           |                 |                        |             |
///  17*N |------------------------------------------------------|-------------|
///       |  C_{R_i}  | bucket[r·ϕ^i]_k |   r·ϕ^i·C_{R_i}        |  newbucket  |
///       |           |                 |                        |             |
///       |           |                 |                        |             |
///  34*N |------------------------------------------------------|-------------|
///       |  C_{L}    |  C_{R}          |    C_{L} + C_{R}'      |    C_{O}'   | // assert that C_O' == C_O
/// 35*N  |------------------------------------------------------|-------------|
///
///
///           The mystery block (undefined now)
///      |-------------------------------------------|
///      |   default_instance                        |
///      |   computing error term T (one line)       |
/// 2^15 |---- --------------------------------------|
///```
///
/// Counting cells:
/// - Inputs:              2 * 17 * 3N = 102N
/// - Inputs repacked 75:  2 * 4 * 3N = 24N
/// - Inputs repacked 150: 2 * 2 * 3N = 12N
/// - Hashes:              2 * 165 * 3N = 990N (max 4 * 165 * 3N if we add 165 constants to every call)
/// - scalars:             4 N + 17 * 3 * N = 55 N
/// - ECADDs:              230 * 35 * N = 8050N
/// Total (CELL):         ~9233*N
///
///     ...which is less than 32k*N
///
/// We can calculate N_IVC as dependency of N_APP in this way:
///    N = N_APP + (CELL/2^15)*N
///    (1 - CELL/2^15)*N = N_APP
///    N = (1/(1 - CELL/2^15)) * N_APP = (2^15 / (2^15 - CELL)) * N_APP
///    N_IVC = (1/(1 - CELL/2^15) - 1) * N_APP = (2^15 / (2^15 - CELL) - 1) * N_APP
///
/// In our particular case, CELL = 9233, so
///    N_IVC = 0.39 N_APP
///
/// Which means for e.g. 50 columns we'll need extra 20 of IVC.

// NB: We can reuse hash constants.
// TODO: Can we pass just one coordinate and sign (x, sign) instead of (x,y) for hashing?
#[derive(Debug, Clone, PartialEq)]
pub enum IVCColumn {
    /// 2*17 15-bit limbs (two base field points)
    Block1Input(usize),
    /// 2*4 75-bit limbs
    Block1InputRepacked75(usize),
    /// 2*2 150-bit limbs
    Block1InputRepacked150(usize),

    /// 1 hash per row
    Block2Hash(PoseidonColumn<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>),

    /// Constant phi
    Block3ConstPhi,
    /// Constant r
    Block3ConstR,
    /// Scalar coeff #1, powers of Phi, phi^i
    Block3PhiPow,
    /// Scalar coeff #2, r * phi^i
    Block3PhiPowR,
    /// 17 15-bit limbs
    Block3PhiPowLimbs(usize),
    /// 17 15-bit limbs
    Block3PhiPowRLimbs(usize),

    /// 1 addition per row
    Block4ECAdd(FECColumn),
}

impl ColumnIndexer for IVCColumn {
    // This should be
    //   const COL_N: usize = std::cmp::max(IVCPoseidonColumn::COL_N, FECColumn::COL_N);
    // which is runtime-only expression..?
    const COL_N: usize = IVCPoseidonColumn::COL_N;

    fn to_column(self) -> Column {
        match self {
            IVCColumn::Block1Input(i) => {
                assert!(i < 2 * N_LIMBS_SMALL);
                Column::X(i)
            }
            IVCColumn::Block1InputRepacked75(i) => {
                assert!(i < 2 * N_LIMBS_LARGE);
                Column::X(2 * N_LIMBS_SMALL + i)
            }
            IVCColumn::Block1InputRepacked150(i) => {
                assert!(i < 2 * N_LIMBS_XLARGE);
                Column::X(2 * N_LIMBS_SMALL + 2 * N_LIMBS_LARGE + i)
            }
            IVCColumn::Block2Hash(poseidon_col) => poseidon_col.to_column(),
            IVCColumn::Block3ConstPhi => Column::X(0),
            IVCColumn::Block3ConstR => Column::X(1),
            IVCColumn::Block3PhiPow => Column::X(2),
            IVCColumn::Block3PhiPowR => Column::X(3),
            IVCColumn::Block3PhiPowLimbs(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(4 + i)
            }
            IVCColumn::Block3PhiPowRLimbs(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(4 + N_LIMBS_SMALL + i)
            }
            IVCColumn::Block4ECAdd(fec_col) => fec_col.to_column(),
        }
    }
}

pub struct IVCHashLens {}

impl MPrism for IVCHashLens {
    type Source = IVCColumn;
    type Target = IVCPoseidonColumn;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            IVCColumn::Block2Hash(col) => Some(col),
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        IVCColumn::Block2Hash(target)
    }
}
