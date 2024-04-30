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
///                                                  (repacked 150)          ϕ^i    same ϕs but
///                                      (repacked 75)             (hashes)   r*ϕ^i  in 17 limbs       153
///         Input1     Input2     Input3    R1  R2  R3 R1 R2 R3   H1 ... H12    -ϕ^i   each         FEC ADDs
///  1   |----------|----------|----------|---|---|---|--|--|--|-------------|-|-|-|---|---|---|----------------|
///      |   C_L1   |   C_L2   |   C_L3   |           |        |             |     |           |                |
///      |   C_L4   |   C_L5   |   ...    |           |        |             |     |           |                |
///      |   ...    |   ...    |   ...    |           |        |             |     |           |                |
/// N/3  |----------|----------|----------|           |        |             |     |           |                |
///      |   C_R1   |   C_R2   |   C_R3   |           |        |             |     |           |                |
///      |   ...    |   ...    |   ...    |           |        |             |     |           |                |
/// 2N/3 |----------|----------|----------|           |        |             |     |           |                |
///      |   C_O1   |   C_O2   |   C_O3   |           |        |             |     |           |                |
///      |   ...    |   ...    |   ...    |           |        |             |     |           |                |
/// N    |----------|----------|----------|-----------|--------|-------------|-----|-----------|----------------|
/// N+1  |        default_instance?       |
///      |            ....
///      |  ...??? empty space? reuse w/ selectors?
/// 2^15 |---------------
///```

#[derive(Debug, Clone, PartialEq)]
pub enum IVCColumn {
    /// 1/3 section, containing 2*17 15-bit limbs (two base field points)
    Input1(usize),
    /// 2/3 section, containing 2*17 15-bit limbs
    Input2(usize),
    /// 3/3 section, containing 2*17 15-bit limbs
    Input3(usize),
    /// 1/3 section, containing 2*4 75-bit limbs
    Input1Repacked75(usize),
    /// 2/3 section, containing 2*4 75-bit limbs
    Input2Repacked75(usize),
    /// 3/3 section, containing 2*4 75-bit limbs
    Input3Repacked75(usize),
    /// 1/3 section, containing 2*2 150-bit limbs
    Input1Repacked150(usize),
    /// 2/3 section, containing 2*2 150-bit limbs
    Input2Repacked150(usize),
    /// 3/3 section, containing 2*2 150-bit limbs
    Input3Repacked150(usize),
    /// We need to absorb 12 elements per row (3 inputs = 6 base field
    /// elements = 12 limbs of 150bit)
    Hashes(
        PoseidonColumn<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>,
        usize,
    ),
    /// Scalar coeff #1
    Phi,
    /// Scalar coeff #2
    PhiR,
    /// Scalar coeff #3
    // minor optimisation: maybe we don't need minus phi.
    PhiMinus,
    /// 17 15-bit limbs
    PhiLimbs(usize),
    /// 17 15-bit limbs
    PhiRLimbs(usize),
    /// 17 15-bit limbs
    PhiMinusLimbs(usize),
    /// 17 * 3 * 3 additions per row.
    ///
    /// We have 3 inputs per row (#1 #2 #3), each one in 4 75-bit
    /// limbs. We have 3 coefficients (phi, -phi, phi*r) for each
    /// input, each in 17 limbs. Note that coefficients are generally
    /// located on a different row, so must be looked up.
    ECAdds(FECColumn, usize),
}

impl ColumnIndexer for IVCColumn {
    // 192 + 12 * HASH + 53 * ECADD
    const COL_N: usize = 3 * 2 * N_LIMBS_SMALL
        + 3 * 2 * 4
        + 3 * 2 * 2
        + 12 * PoseidonColumn::<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>::COL_N
        + 3
        + 3 * N_LIMBS_SMALL
        + N_LIMBS_SMALL * 3 * 3;

    fn to_column(self) -> Column {
        todo!()
    }
}
