use crate::circuits::{
    expr::{self, Domain, GenericColumn},
    gate::{CurrOrNext, GateType},
    lookup::lookups::LookupPattern,
};
use serde::{Deserialize, Serialize};
use CurrOrNext::{Curr, Next};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// A type representing one of the polynomials involved in the PLONK IOP.
pub enum Column {
    Witness(usize),
    Z,
    LookupSorted(usize),
    LookupAggreg,
    LookupTable,
    LookupKindIndex(LookupPattern),
    LookupRuntimeSelector,
    LookupRuntimeTable,
    Index(GateType),
    Coefficient(usize),
    Permutation(usize),
}

impl GenericColumn for Column {
    fn domain(&self) -> Domain {
        match self {
            Column::Index(GateType::Generic) => Domain::D4,
            Column::Index(GateType::CompleteAdd) => Domain::D4,
            _ => Domain::D8,
        }
    }
}

impl Column {
    pub fn latex(&self) -> String {
        match self {
            Column::Witness(i) => format!("w_{{{i}}}"),
            Column::Z => "Z".to_string(),
            Column::LookupSorted(i) => format!("s_{{{i}}}"),
            Column::LookupAggreg => "a".to_string(),
            Column::LookupTable => "t".to_string(),
            Column::LookupKindIndex(i) => format!("k_{{{i:?}}}"),
            Column::LookupRuntimeSelector => "rts".to_string(),
            Column::LookupRuntimeTable => "rt".to_string(),
            Column::Index(gate) => {
                format!("{gate:?}")
            }
            Column::Coefficient(i) => format!("c_{{{i}}}"),
            Column::Permutation(i) => format!("sigma_{{{i}}}"),
        }
    }

    pub fn text(&self) -> String {
        match self {
            Column::Witness(i) => format!("w[{i}]"),
            Column::Z => "Z".to_string(),
            Column::LookupSorted(i) => format!("s[{i}]"),
            Column::LookupAggreg => "a".to_string(),
            Column::LookupTable => "t".to_string(),
            Column::LookupKindIndex(i) => format!("k[{i:?}]"),
            Column::LookupRuntimeSelector => "rts".to_string(),
            Column::LookupRuntimeTable => "rt".to_string(),
            Column::Index(gate) => {
                format!("{gate:?}")
            }
            Column::Coefficient(i) => format!("c[{i}]"),
            Column::Permutation(i) => format!("sigma_[{i}]"),
        }
    }
}

impl expr::Variable<Column> {
    pub fn ocaml(&self) -> String {
        format!("var({:?}, {:?})", self.col, self.row)
    }

    pub fn latex(&self) -> String {
        let col = self.col.latex();
        match self.row {
            Curr => col,
            Next => format!("\\tilde{{{col}}}"),
        }
    }

    pub fn text(&self) -> String {
        let col = self.col.text();
        match self.row {
            Curr => format!("Curr({col})"),
            Next => format!("Next({col})"),
        }
    }
}
