use crate::{
    columns::{Column, ColumnIndexer},
    serialization::interpreter::{N_LIMBS_LARGE, N_LIMBS_SMALL},
};

/// Number of columns in the FEC circuits.
pub const FEC_N_COLUMNS: usize = 5 * N_LIMBS_LARGE + 12 * N_LIMBS_SMALL + 9;

/// Columns used by the serialization subcircuit.
pub enum FECColumn {
    XP(usize),
    YP(usize),
    XQ(usize),
    YQ(usize),
    F(usize),
    XR(usize),
    YR(usize),
    S(usize),
    Q1(usize),
    Q2(usize),
    Q3(usize),
    Q1Sign,
    Q2Sign,
    Q3Sign,
    Carry1(usize),
    Carry2(usize),
    Carry3(usize),
}

impl ColumnIndexer for FECColumn {
    const COL_N: usize = FEC_N_COLUMNS;
    fn to_column(self) -> Column {
        match self {
            FECColumn::XP(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::X(i)
            }
            FECColumn::YP(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::X(N_LIMBS_LARGE + i)
            }
            FECColumn::XQ(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::X(2 * N_LIMBS_LARGE + i)
            }
            FECColumn::YQ(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::X(3 * N_LIMBS_LARGE + i)
            }
            FECColumn::F(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::X(4 * N_LIMBS_LARGE + i)
            }
            FECColumn::XR(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(5 * N_LIMBS_LARGE + i)
            }
            FECColumn::YR(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(5 * N_LIMBS_LARGE + N_LIMBS_SMALL + i)
            }
            FECColumn::S(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(5 * N_LIMBS_LARGE + 2 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q1(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(5 * N_LIMBS_LARGE + 3 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q2(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(5 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q3(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::X(5 * N_LIMBS_LARGE + 5 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q1Sign => Column::X(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL),
            FECColumn::Q2Sign => Column::X(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 1),
            FECColumn::Q3Sign => Column::X(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 2),
            FECColumn::Carry1(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::X(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 3 + i)
            }
            FECColumn::Carry2(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::X(5 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL + 5 + i)
            }
            FECColumn::Carry3(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::X(5 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL + 7 + i)
            }
        }
    }
}
