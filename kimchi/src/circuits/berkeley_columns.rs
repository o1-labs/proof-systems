use crate::{
    circuits::{
        expr::{self, ColumnEvaluations, Domain, ExprError, GenericColumn},
        gate::{CurrOrNext, GateType},
        lookup::lookups::LookupPattern,
    },
    proof::{PointEvaluations, ProofEvaluations},
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

impl<F: Copy> ColumnEvaluations<F> for ProofEvaluations<PointEvaluations<F>> {
    type Column = Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        use Column::*;
        let l = self.lookup.as_ref().ok_or(ExprError::LookupShouldNotBeUsed);
        match col {
            Witness(i) => Ok(self.w[i]),
            Z => Ok(self.z),
            LookupSorted(i) => l.map(|l| l.sorted[i]),
            LookupAggreg => l.map(|l| l.aggreg),
            LookupTable => l.map(|l| l.table),
            LookupRuntimeTable => l.and_then(|l| l.runtime.ok_or(ExprError::MissingRuntime)),
            Index(GateType::Poseidon) => Ok(self.poseidon_selector),
            Index(GateType::Generic) => Ok(self.generic_selector),
            Permutation(i) => Ok(self.s[i]),
            Coefficient(i) => Ok(self.coefficients[i]),
            LookupKindIndex(_) | LookupRuntimeSelector | Index(_) => {
                Err(ExprError::MissingIndexEvaluation(col))
            }
        }
    }
}
