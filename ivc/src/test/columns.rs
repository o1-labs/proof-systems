use kimchi_msm::columns::{Column, ColumnIndexer};
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, EnumIter, EnumCountMacro, Hash)]
pub enum AdditionColumn {
    A,
    B,
    C,
}

impl ColumnIndexer for AdditionColumn {
    const N_COL: usize = 3;

    fn to_column(self) -> Column {
        match self {
            AdditionColumn::A => Column::Relation(0),
            AdditionColumn::B => Column::Relation(1),
            AdditionColumn::C => Column::Relation(2),
        }
    }
}
