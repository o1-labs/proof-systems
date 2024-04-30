use crate::poseidon::columns::PoseidonColumn;
use kimchi_msm::{
    columns::{Column, ColumnIndexer},
    fec::columns::FECColumn,
    serialization::interpreter::N_LIMBS_SMALL,
};

pub const IVC_POSEIDON_STATE_SIZE: usize = 3;
pub const IVC_POSEIDON_NB_FULL_ROUND: usize = 55;

/// N := N_IVC + N_APP is the total number of columns in the circuit.
///
///```text
///           34         34         34      8   8   8  4  4  4             constϕ
///                                                  (repacked 150)          ϕ^i    same ϕs but
///                                      (repacked 75)             (hashes)   r*ϕ^i  in 17 limbs       153
///         Input1     Input2     Input3    R1  R2  R3 R1 R2 R3   H1 ... H6     -ϕ^i   each         FEC ADDs
///  1   |----------|----------|----------|---|---|---|--|--|--|-------------|-|-|-|-|---|---|---|----------------|
///      |   C_L1   |   C_L2   |   C_L3   |           |        |             |       |           |                |
///      |   C_L4   |   C_L5   |   ...    |           |        |             |       |           |                |
///      |   ...    |   ...    |   ...    |           |        |             |       |           |                |
/// N/3  |----------|----------|----------|           |        |             |       |           |                |
///      |   C_R1   |   C_R2   |   C_R3   |           |        |             |       |           |                |
///      |   ...    |   ...    |   ...    |           |        |             |       |           |                |
/// 2N/3 |----------|----------|----------|           |        |             |       |           |                |
///      |   C_O1   |   C_O2   |   C_O3   |           |        |             |       |           |                |
///      |   ...    |   ...    |   ...    |           |        |             |       |           |                |
/// N    |----------|----------|----------|-----------|--------|-------------|-------|-----------|----------------|
/// N+1  |        default_instance?       |
///      |            ....                |              ...       FEC ADDs       ...
///      |  ...??? empty space?
///      |     reuse w/ selectors?
/// 2^15 |---------------
///```
///
/// Counting cells:
/// - Inputs:              2 * 17 * 3N = 102N
/// - Inputs repacked 75:  2 * 4 * 3N = 24N
/// - Inputs repacked 150: 2 * 2 * 3N = 12N
/// - Hashes:              2 * 165 * 3N = 990N (max 4 * 165 * 3N if we add 165 constants to every call)
/// - scalars:             4 N + 17 * 3 * N = 55 N
/// - ECADDs:              230 * 35 * 3N = 24150N
/// Total:                 25333*N
///
///       which is less than 32k*N
///
/// We can calculate N_IVC as dependency of N_APP in this way:
///    N = N_APP + (CELL/2^15)*N
///    (1 - CELL/2^15)*N = N_APP
///    N = (1/(1 - CELL/2^15)) * N_APP = (2^15 / (2^15 - CELL)) * N_APP
///    N_IVC = (1/(1 - CELL/2^15) - 1) * N_APP = (2^15 / (2^15 - CELL) - 1) * N_APP
///
/// In our particular case, CELL = 25333, so
///    N_IVC = 3.41 N_APP
///
/// It is also useful to know that N / 2^15 = N_APP / (2^15 - CELL).
/// In our case it means that N / 2^15 = N_APP / 7414, so if e.g.
/// N_APP < 2170, N / 2^15 > 3 which means we can fit all 3N
/// commitments in a single column!
///
/// I'm hopeful that this is the case, in which case the design will be as follows:
///
/// Layout under assumption that 3N < 2^15!
///```text
///           34      8    4        constϕ
///                                   ϕ^i    same ϕs but
///                                    r*ϕ^i  in 17 limbs      35*3 - BOT
///         Input1    R75 R150  H1 H2    -ϕ^i   each         FEC ADDs
///  1   |----------|----|----|-------|-|-|-|-|---|---|---|----------------|
///      |   C_L1   |    |    |       |       |           |                |
///      |   C_L2   |    |    |       |       |           |                |
///      |   ...    |    |    |       |       |           |                |
///   N  |----------|    |    |       |       |           |                |
///      |   C_R1   |    |    |       |       |           |                |
///      |   ...    |    |    |       |       |           |                |
///  2N  |----------|    |    |       |       |           |                |
///      |   C_O1   |    |    |       |       |           |                |
///      |   ...    |    |    |       |       |           |                |
///  3N  |----------|----|----|-------|-------|-----------|----------------|
///      |        default_instance?                                        |
///      |                      ....... BOT FEC ADDs .......               |
/// 2^15 |-----------------------------------------------------------------|
///```
///
///

// NB: We can reuse hash constants.
// TODO: Can we pass just one coordinate and sign (x, sign) instead of (x,y) for hashing?
#[derive(Debug, Clone, PartialEq)]
pub enum IVCColumn {
    /// 2*17 15-bit limbs (two base field points)
    Input(usize),
    /// 2*4 75-bit limbs
    InputRepacked75(usize),
    /// 2*2 150-bit limbs
    InputRepacked150(usize),
    /// We need to absorb 4 elements per row (1 input = 2 base field
    /// elements = 4 limbs of 150bit).
    ///
    /// We can hash 2 elements at the same time, so 6 hash invocations.
    ///
    /// NB: We can probably even do more absorbing.
    Hashes(
        PoseidonColumn<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>,
        usize,
    ),
    /// Constant phi
    ConstPhi,
    /// Constant r
    ConstR,
    /// Scalar coeff #1, phi^i
    Phi,
    /// Scalar coeff #2, r * phi^i
    PhiR,
    /// Scalar coeff #3, -phi^i
    // minor optimisation: maybe we don't need minus phi.
    PhiMinus,
    /// 17 15-bit limbs
    PhiLimbs(usize),
    /// 17 15-bit limbs
    PhiRLimbs(usize),
    /// 17 15-bit limbs
    PhiMinusLimbs(usize),
    /// 35 additions per row at most.
    ///
    /// We have 1 input per row, each one requires 2*17+1 ECAdds. Note
    /// that coefficients are generally located on a different row, so
    /// must be looked up.
    ECAdds(FECColumn, usize),
    /// Overlapping, bottom ECADDs
    ECAddsBottom(FECColumn, usize),
}

impl ColumnIndexer for IVCColumn {
    const COL_N: usize = 2 * N_LIMBS_SMALL
        + 2 * 4
        + 2 * 2
        + 2 * PoseidonColumn::<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>::COL_N
        + 4
        + 3 * N_LIMBS_SMALL
        + 35 * FECColumn::COL_N;

    fn to_column(self) -> Column {
        todo!()
    }
}
