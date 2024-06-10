use crate::{ivc::interpreter::N_LIMBS_XLARGE, poseidon::columns::PoseidonColumn};
use kimchi_msm::{
    circuit_design::composition::MPrism,
    columns::{Column, ColumnIndexer},
    fec::columns::{FECColumn, FECColumnInput, FECColumnInter, FECColumnOutput},
    serialization::interpreter::{N_LIMBS_LARGE, N_LIMBS_SMALL},
};

/// Number of blocks in the circuit.
pub const N_BLOCKS: usize = 6;

/// Defines the height of each block in the IVC circuit.
pub fn block_height<const N_COL_TOTAL: usize, const N_CHALS: usize>(block_num: usize) -> usize {
    match block_num {
        0 => 3 * N_COL_TOTAL,
        1 => 6 * N_COL_TOTAL + 2,
        2 => N_COL_TOTAL + 1,
        3 => 35 * N_COL_TOTAL + 5,
        4 => N_CHALS,
        5 => 1,
        _ => panic!("block_size: no block number {block_num:?}"),
    }
}

pub const IVC_POSEIDON_STATE_SIZE: usize = 3;
pub const IVC_POSEIDON_NB_FULL_ROUND: usize = 55;

pub type IVCPoseidonColumn = PoseidonColumn<IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>;

/// The IVC circuit is tiled vertically. We assume we have as many
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
///         Inputs:
///      Each point is 2 base field coordinates in 17 15-bit limbs
///       recomposed as 8 75-bit limbs
///       recomposed as 4 150-bit limbs.
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
///  2N  |------------------------------------------|   must be equal to public input!
///      |                                          |                    (H_i in nova)
///      |                                         .| . here is h_r
///  4N  |------------------------------------------|
///      |                                          |
///      |                                         .| . here is h_o, equal to H_{i+1} in Nova
///  6N  |------------------------------------------|
///      |                                         .| r = h_lr = h(h_l,h_r)
///      |                                         .| ϕ = h_lro = h(r,h_o)
/// 6N+2 |------------------------------------------|
///       TODO: we also need to squeeze challenges for
///       the right (strict) instance: β, γ, j (joint_combiner)
///
///
/// Scalars block.
///
/// Most of the r^2 and r^3 cells are /unused/, and this design can be
/// much more optimal if r^2|r^3 elements come in a separate block.
/// But the overhead is not big and it's a very easy layout, so
/// keeping it for now.
///
///     constϕ
///         constr
///                ϕ^i             r^3·ϕ^i    ϕ^i        r*ϕ^i        r^2·ϕ^i_k    r^3·ϕ^i_k
///                      r*ϕ^i             in 17 limbs  in 17 limbs      ...         ...
///                           r^2·ϕ^i         each        each
///   1  |---|---|-----|-------|----|----|------------|------------|------------|------------|
///      | ϕ   r    ϕ     rϕ    r^2ϕ r^3ϕ|            |            |            |            |
///      | ϕ   r   ϕ^2   rϕ^2            |            |            |            |            |
///      | ϕ   r   ϕ^3   rϕ^3            |            |            |            |            |
///      |                               |            |            |            |            |
///      |                               |            |            |            |            |
///      |                               |            |            |            |            |
///  i   |                               |            |            |            |            |
///      |                               |            |            |            |            |
///      |                               |            |            |            |            |
///      |                               |            |            |            |            |
///      |       ϕ^{N+1}                 |            |            |            |            |
///  N+1 |-------------------------------|------------|------------|------------|------------|
///       1    2   3   4      5      6   ...        6+17          6+2*17                    6+4*17
///
///

///
/// We compute the following equations, where equations in "quotes" are
/// what we /want/ to prove, and non-quoted is an equavilant version
/// that we actually prove instead:
/// - "C_{O,i} = C_{L,i} + r·C_{R,i}":
///   - C_{O,i} = C_{L,i} + C_{R',i}
///   - "C_{R',i} = r·C_{R,i}"
///     - bucket[(ϕ^i)_k] -= C_{R',i}
///     - bucket[(r·ϕ^i)_k] += C_{R,i}
/// - "E_O = E_L + r·T_0 + r^2·T_1 + r^3·E_R":
///   - E_O = E_L + E_R'
///   - "E_R' = r·T_0 + r^2·T_1 + r^3·E_R"
///     - bucket[(ϕ^{n+1})_k] += E_R'
///     - bucket[(r·ϕ^{n+1})_k] += T_0
///     - bucket[(r^2·ϕ^{n+1})_k] += T_1
///     - bucket[(r^3·ϕ^{n+1})_k] += E_R
///
/// Runtime access time is represented by ? because it's not known in advance.
///
/// Output and input RAM invocations in the same row use the same coeff/memory index.
///
/// TODO FIXME we need to write into /different/ buckets.
///
/// FEC Additions, one per row, each one is ~230 columns:
///
///                  .           input #2 (looked up)                  .                  Output
///                  .                  Access        input#2          .     FEC ADD      access    output
///          input#1 .  Coeff/mem ix     Time         Value            .   computation     time     value
///   1   |-------------------------------------------------------------------------------|-----|------------|
///       | C_{R',1} | ϕ^1_0           |  ?  | bucket[ϕ^1_0]           |                  |  ?  | newbucket  |
///       | C_{R',2} | ϕ^2_0           |  ?  | bucket[ϕ^2_0]           |                  |  ?  | newbucket  |
///       |          |      ...        | ... |                         |                  | ... |            |
///       | C_{R',N} | ϕ^N_0           |  ?  | bucket[ϕ^N_0]           |                  |  ?  | newbucket  |
///       | C_{R',1} | ϕ^1_1           |  ?  | bucket[ϕ^0_1]           |                  |  ?  | newbucket  |
///       |          |      ...        | ... |                         |                  | ... |            |
///       | C_{R',i} | ϕ^i_k           |  ?  | bucket[ϕ^i_k]           |                  |  ?  | newbucket  |
///       |          |                 |     |                         |                  |     |            |
///       |          |      ...        | ... |                         |                  | ... |            |
///  17*N |--------------------------------------------------------------------------------------------------|
///       | C_{R,i}  | r·(ϕ^i_k)       |  ?  | bucket[r·(ϕ^i_k)]       |                  |  ?  | newbucket  |
///       |          |                 |     |                         |                  |     |            |
///       |          |      ...        | ... |                         |                  | ... |            |
///  34*N |--------------------------------------------------------------------------------------------------|
///       |-C_{R',i} |      -          |  -  | C_{L,i}                 |                  |  -  | C_{O,i}    |
///       |          |     ...         | ... |                         |                  | ... |            |
///  35*N |--------------------------------------------------------------------------------------------------|
///       | -E_R'    | ϕ^{n+1}_k       |  ?  | bucket[ϕ^{n+1}_k]       |                  |     | newbucket  |
///       |          |     ...         | ... |                         |                  | ... |            |
///       |  T_0     | r·(ϕ^{n+1})     |  ?  | bucket[r·(ϕ^{n+1})]     |                  |     | newbucket  |
///       |          |     ...         | ... |                         |                  | ... |            |
///       |  T_1     | r^2·(ϕ^{n+1}_k) |  ?  | bucket[r^2·(ϕ^{n+1}_k)] |                  |     | newbucket  |
///       |          |     ...         | ... |                         |                  | ... |            |
///       |  E_R     | r^3·(ϕ^{n+1}_k) |  ?  | bucket[r^3·(ϕ^{n+1}_k)] |                  |     | newbucket  |
///       |          |     ...         | ... |                         |                  | ... |            |
/// 35*N+ |  E_L     |      -          |  -  |      E_R'               |                  |  -  |    E_O     |
/// 4*17+ |--------------------------------------------------------------------------------------------------|
/// 1
///
///
///   TODO: add different challenges: β, γ, joint_combiner
/// Challenges block.
///
///            relaxed
///                       strict
///                    (relaxed in-place)
///        r   α_{L,i}    α_{R}^i     α_{O,i}
///  1    |--|--------|-----------|-----------------------|
///       |  |        | α_R = h_R |                       |
///       |  |        |           |                       |
///       |  |        |           |                       |
///       |  |        | α_R^i     | α_{L,i} + r·α_{R,i}^i |
///       |  |        |           |                       |
///       |  |        |           |                       |
///       |  |        |           |                       |
///       |  |        |           |                       |
///       |  |        |           |                       |
///       |  |        |           |                       |
/// #chal |--|--------|-----------|-----------------------|
///
/// #chal is the number of constraints. Our optimistic expectation is
/// that it is around const*N for const < 3.
///
///
/// "u" block. In the general form we want to prove
/// u_O = u_L + r·u_R, but u_R = 0, so we prove
/// u_O = u_L + r.
///
///     r    u_L       u_O = u_L + r
///    |--|--------|--------------------|
///    |--|--------|--------------------|
///
///
/// 2^15 |---- --------------------------------------|
///```
///
///
/// Assume that IVC circuit takess CELL cells, e.g. CELL = 10000*N.
/// Then we can calculate N_IVC as dependency of N_APP in this way:
///    N = N_APP + (CELL/2^15)*N
///    (1 - CELL/2^15)*N = N_APP
///    N = (1/(1 - CELL/2^15)) * N_APP = (2^15 / (2^15 - CELL)) * N_APP
///    N_IVC = (1/(1 - CELL/2^15) - 1) * N_APP = (2^15 / (2^15 - CELL) - 1) * N_APP
///
///
/// --- (slightly) OUTDATED BELOW ---
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
/// In our particular case, CELL = 9233, so
///    N_IVC = 0.39 N_APP
///
/// Which means for e.g. 50 columns we'll need extra 20 of IVC.

// NB: We can reuse hash constants.
// TODO: Can we pass just one coordinate and sign (x, sign) instead of (x,y) for hashing?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IVCColumn {
    /// A single column containing the folding iteration number,
    /// starting with 0 for the base case, and non-zero positive for
    /// inductive case.
    FoldIteration,

    /// Selector for blocks. Inner usize is ∈ [0,#blocks).
    BlockSel(usize),

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
    /// Scalar coeff #2, r^2 * phi^i
    Block3PhiPowR2,
    /// Scalar coeff #2, r^3 * phi^i
    Block3PhiPowR3,
    /// 17 15-bit limbs
    Block3PhiPowLimbs(usize),
    /// 17 15-bit limbs
    Block3PhiPowRLimbs(usize),
    /// 17 15-bit limbs
    Block3PhiPowR2Limbs(usize),
    /// 17 15-bit limbs
    Block3PhiPowR3Limbs(usize),

    /// 2*4 75-bit limbs
    Block4Input1(usize),
    /// Coeffifient which is indexing a bucket. Used for both lookups in this row.
    Block4Coeff,
    /// RAM lookup access time for input 1.
    Block4Input2AccessTime,
    /// 2*4 75-bit limbs
    Block4Input2(usize),
    /// EC ADD intermediate wires
    Block4ECAddInter(FECColumnInter),
    /// 2*17 15-bit limbs
    Block4OutputRaw(FECColumnOutput),
    // TODO: this might be just Input2AccessTime + 1?
    /// RAM lookup access time for output.
    Block4OutputAccessTime,
    /// 2*4 75-bit limbs
    Block4OutputRepacked(usize),

    /// Constant h_r
    Block5ConstHr,
    /// Constant r
    Block5ConstR,
    /// α_{L,i}
    Block5ChalLeft,
    /// α_R^i, where α_R = h_R
    Block5ChalRight,
    /// α_{O,i} = α_{L,i} + r·α_R^i
    Block5ChalOutput,

    /// Constant r
    Block6ConstR,
    /// u_L
    Block6ULeft,
    /// u_O = u_L + r
    Block6UOutput,
}

impl ColumnIndexer for IVCColumn {
    // This should be
    //   const N_COL: usize = std::cmp::max(IVCPoseidonColumn::N_COL, FECColumn::N_COL);
    // which is runtime-only expression..?
    // 333 is not enough
    const N_COL: usize = 400;

    fn to_column(self) -> Column {
        match self {
            IVCColumn::FoldIteration => Column::Relation(0),

            IVCColumn::BlockSel(i) => {
                assert!(i < N_BLOCKS);
                Column::FixedSelector(i)
            }

            block => (match block {
                IVCColumn::Block1Input(i) => {
                    assert!(i < 2 * N_LIMBS_SMALL);
                    Column::Relation(i)
                }
                IVCColumn::Block1InputRepacked75(i) => {
                    assert!(i < 2 * N_LIMBS_LARGE);
                    Column::Relation(2 * N_LIMBS_SMALL + i)
                }
                IVCColumn::Block1InputRepacked150(i) => {
                    assert!(i < 2 * N_LIMBS_XLARGE);
                    Column::Relation(2 * N_LIMBS_SMALL + 2 * N_LIMBS_LARGE + i)
                }

                IVCColumn::Block2Hash(poseidon_col) => poseidon_col.to_column(),

                IVCColumn::Block3ConstPhi => Column::Relation(0),
                IVCColumn::Block3ConstR => Column::Relation(1),
                IVCColumn::Block3PhiPow => Column::Relation(2),
                IVCColumn::Block3PhiPowR => Column::Relation(3),
                IVCColumn::Block3PhiPowR2 => Column::Relation(4),
                IVCColumn::Block3PhiPowR3 => Column::Relation(5),
                IVCColumn::Block3PhiPowLimbs(i) => {
                    assert!(i < N_LIMBS_SMALL);
                    Column::Relation(6 + i)
                }
                IVCColumn::Block3PhiPowRLimbs(i) => {
                    assert!(i < N_LIMBS_SMALL);
                    Column::Relation(6 + N_LIMBS_SMALL + i)
                }
                IVCColumn::Block3PhiPowR2Limbs(i) => {
                    assert!(i < N_LIMBS_SMALL);
                    Column::Relation(6 + 2 * N_LIMBS_SMALL + i)
                }
                IVCColumn::Block3PhiPowR3Limbs(i) => {
                    assert!(i < N_LIMBS_SMALL);
                    Column::Relation(6 + 3 * N_LIMBS_SMALL + i)
                }

                IVCColumn::Block4Input1(i) => {
                    assert!(i < 2 * N_LIMBS_LARGE);
                    Column::Relation(i)
                }
                IVCColumn::Block4Coeff => Column::Relation(8),
                IVCColumn::Block4Input2AccessTime => Column::Relation(9),
                IVCColumn::Block4Input2(i) => {
                    assert!(i < 2 * N_LIMBS_LARGE);
                    Column::Relation(10 + i)
                }
                IVCColumn::Block4ECAddInter(fec_inter) => fec_inter.to_column().add_rel_offset(18),
                IVCColumn::Block4OutputRaw(fec_output) => fec_output
                    .to_column()
                    .add_rel_offset(18 + FECColumnInter::N_COL),
                IVCColumn::Block4OutputAccessTime => {
                    Column::Relation(18 + FECColumnInter::N_COL + FECColumnOutput::N_COL)
                }
                IVCColumn::Block4OutputRepacked(i) => {
                    assert!(i < 2 * N_LIMBS_LARGE);
                    Column::Relation(18 + FECColumnInter::N_COL + FECColumnOutput::N_COL + 1 + i)
                }

                IVCColumn::Block5ConstHr => Column::Relation(0),
                IVCColumn::Block5ConstR => Column::Relation(1),
                IVCColumn::Block5ChalLeft => Column::Relation(2),
                IVCColumn::Block5ChalRight => Column::Relation(3),
                IVCColumn::Block5ChalOutput => Column::Relation(4),

                IVCColumn::Block6ConstR => Column::Relation(0),
                IVCColumn::Block6ULeft => Column::Relation(1),
                IVCColumn::Block6UOutput => Column::Relation(2),

                _ => panic!("Column selection not possible."),
            })
            .add_rel_offset(1),
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

pub struct IVCFECLens {}

impl MPrism for IVCFECLens {
    type Source = IVCColumn;
    type Target = FECColumn;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            IVCColumn::Block4Input1(i) => {
                if i < 4 {
                    Some(FECColumn::Input(FECColumnInput::XP(i)))
                } else {
                    Some(FECColumn::Input(FECColumnInput::YP(i)))
                }
            }
            IVCColumn::Block4Input2(i) => {
                if i < 4 {
                    Some(FECColumn::Input(FECColumnInput::XQ(i)))
                } else {
                    Some(FECColumn::Input(FECColumnInput::YQ(i)))
                }
            }
            IVCColumn::Block4OutputRaw(output) => Some(FECColumn::Output(output)),
            IVCColumn::Block4ECAddInter(inter) => Some(FECColumn::Inter(inter)),
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        match target {
            FECColumn::Input(FECColumnInput::XP(i)) => IVCColumn::Block4Input1(i),
            FECColumn::Input(FECColumnInput::YP(i)) => IVCColumn::Block4Input1(4 + i),
            FECColumn::Input(FECColumnInput::XQ(i)) => IVCColumn::Block4Input2(i),
            FECColumn::Input(FECColumnInput::YQ(i)) => IVCColumn::Block4Input2(4 + i),
            FECColumn::Output(output) => IVCColumn::Block4OutputRaw(output),
            FECColumn::Inter(inter) => IVCColumn::Block4ECAddInter(inter),
        }
    }
}
