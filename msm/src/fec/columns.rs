use crate::{
    columns::{Column, ColumnIndexer},
    serialization::interpreter::{N_LIMBS_LARGE, N_LIMBS_SMALL},
};

/// Number of columns in the FEC circuits.
pub const FEC_N_COLUMNS: usize =
    FECColumnInput::N_COL + FECColumnOutput::N_COL + FECColumnInter::N_COL;

/// FEC ADD inputs: two points = four coordinates, and each in 4
/// "large format" limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FECColumnInput {
    XP(usize), // 4
    YP(usize), // 4
    XQ(usize), // 4
    YQ(usize), // 4
}

/// FEC ADD outputs: one point, each in 17 limb output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FECColumnOutput {
    XR(usize), // 17
    YR(usize), // 17
}

/// FEC ADD intermediate (work) columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FECColumnInter {
    F(usize),      // 4
    S(usize),      // 17
    Q1(usize),     // 17
    Q2(usize),     // 17
    Q3(usize),     // 17
    Q1Sign,        // 1
    Q2Sign,        // 1
    Q3Sign,        // 1
    Q1L(usize),    // 4
    Q2L(usize),    // 4
    Q3L(usize),    // 4
    Carry1(usize), // 36
    Carry2(usize), // 36
    Carry3(usize), // 36
}

/// Columns used by the FEC Addition subcircuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FECColumn {
    Input(FECColumnInput),
    Output(FECColumnOutput),
    Inter(FECColumnInter),
}

impl ColumnIndexer for FECColumnInput {
    const N_COL: usize = 4 * N_LIMBS_LARGE;
    fn to_column(self) -> Column {
        match self {
            FECColumnInput::XP(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(i)
            }
            FECColumnInput::YP(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(N_LIMBS_LARGE + i)
            }
            FECColumnInput::XQ(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(2 * N_LIMBS_LARGE + i)
            }
            FECColumnInput::YQ(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(3 * N_LIMBS_LARGE + i)
            }
        }
    }
}

impl ColumnIndexer for FECColumnOutput {
    const N_COL: usize = 2 * N_LIMBS_SMALL;
    fn to_column(self) -> Column {
        match self {
            FECColumnOutput::XR(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(i)
            }
            FECColumnOutput::YR(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(N_LIMBS_SMALL + i)
            }
        }
    }
}

impl ColumnIndexer for FECColumnInter {
    const N_COL: usize = 4 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL + 9;
    fn to_column(self) -> Column {
        match self {
            FECColumnInter::F(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(i)
            }
            FECColumnInter::S(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(N_LIMBS_LARGE + i)
            }
            FECColumnInter::Q1(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(N_LIMBS_LARGE + N_LIMBS_SMALL + i)
            }
            FECColumnInter::Q2(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(N_LIMBS_LARGE + 2 * N_LIMBS_SMALL + i)
            }
            FECColumnInter::Q3(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(N_LIMBS_LARGE + 3 * N_LIMBS_SMALL + i)
            }
            FECColumnInter::Q1Sign => Column::Relation(N_LIMBS_LARGE + 4 * N_LIMBS_SMALL),
            FECColumnInter::Q2Sign => Column::Relation(N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + 1),
            FECColumnInter::Q3Sign => Column::Relation(N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + 2),
            FECColumnInter::Q1L(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + 3 + i)
            }
            FECColumnInter::Q2L(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(2 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + 3 + i)
            }
            FECColumnInter::Q3L(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(3 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + 3 + i)
            }
            FECColumnInter::Carry1(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::Relation(4 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + 3 + i)
            }
            FECColumnInter::Carry2(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::Relation(4 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 5 + i)
            }
            FECColumnInter::Carry3(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::Relation(4 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL + 7 + i)
            }
        }
    }
}

impl ColumnIndexer for FECColumn {
    const N_COL: usize = FEC_N_COLUMNS;
    fn to_column(self) -> Column {
        match self {
            FECColumn::Input(input) => input.to_column(),
            FECColumn::Inter(inter) => inter.to_column().add_rel_offset(FECColumnInput::N_COL),
            FECColumn::Output(output) => output
                .to_column()
                .add_rel_offset(FECColumnInput::N_COL + FECColumnInter::N_COL),
        }
    }
}
