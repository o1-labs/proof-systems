use crate::{
    columns::{Column, ColumnIndexer},
    serialization::interpreter::{N_LIMBS_LARGE, N_LIMBS_SMALL},
};

/// Number of columns in the FEC circuits.
pub const FEC_N_COLUMNS: usize = 5 * N_LIMBS_LARGE + 12 * N_LIMBS_SMALL + 9;

/// Columns used by the serialization subcircuit.
#[derive(Debug, Clone, PartialEq)]
pub enum FECColumn {
    XP(usize),     // 4
    YP(usize),     // 4
    XQ(usize),     // 4
    YQ(usize),     // 4
    F(usize),      // 4
    XR(usize),     // 17
    YR(usize),     // 17
    S(usize),      // 17
    Q1(usize),     // 17
    Q2(usize),     // 17
    Q3(usize),     // 17
    Q1Sign,        // 1
    Q2Sign,        // 1
    Q3Sign,        // 1
    Carry1(usize), // 36
    Carry2(usize), // 36
    Carry3(usize), // 36
}

impl ColumnIndexer for FECColumn {
    const COL_N: usize = FEC_N_COLUMNS;
    fn to_column(self) -> Column {
        match self {
            FECColumn::XP(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(i)
            }
            FECColumn::YP(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(N_LIMBS_LARGE + i)
            }
            FECColumn::XQ(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(2 * N_LIMBS_LARGE + i)
            }
            FECColumn::YQ(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(3 * N_LIMBS_LARGE + i)
            }
            FECColumn::F(i) => {
                assert!(i < N_LIMBS_LARGE);
                Column::Relation(4 * N_LIMBS_LARGE + i)
            }
            FECColumn::XR(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(5 * N_LIMBS_LARGE + i)
            }
            FECColumn::YR(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(5 * N_LIMBS_LARGE + N_LIMBS_SMALL + i)
            }
            FECColumn::S(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(5 * N_LIMBS_LARGE + 2 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q1(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(5 * N_LIMBS_LARGE + 3 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q2(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(5 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q3(i) => {
                assert!(i < N_LIMBS_SMALL);
                Column::Relation(5 * N_LIMBS_LARGE + 5 * N_LIMBS_SMALL + i)
            }
            FECColumn::Q1Sign => Column::Relation(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL),
            FECColumn::Q2Sign => Column::Relation(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 1),
            FECColumn::Q3Sign => Column::Relation(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 2),
            FECColumn::Carry1(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::Relation(5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + 3 + i)
            }
            FECColumn::Carry2(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::Relation(5 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL + 5 + i)
            }
            FECColumn::Carry3(i) => {
                assert!(i < 2 * N_LIMBS_SMALL + 2);
                Column::Relation(5 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL + 7 + i)
            }
        }
    }
}
