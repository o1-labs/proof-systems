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
        match col {
            Witness(i) => Ok(self.w[i]),
            Z => Ok(self.z),
            LookupSorted(i) => self.lookup_sorted[i].ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupAggreg => self
                .lookup_aggregation
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupTable => self
                .lookup_table
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupRuntimeTable => self
                .runtime_lookup_table
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::Poseidon) => Ok(self.poseidon_selector),
            Index(GateType::Generic) => Ok(self.generic_selector),
            Index(GateType::CompleteAdd) => Ok(self.complete_add_selector),
            Index(GateType::VarBaseMul) => Ok(self.mul_selector),
            Index(GateType::EndoMul) => Ok(self.emul_selector),
            Index(GateType::EndoMulScalar) => Ok(self.endomul_scalar_selector),
            Index(GateType::RangeCheck0) => self
                .range_check0_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::RangeCheck1) => self
                .range_check1_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::ForeignFieldAdd) => self
                .foreign_field_add_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::ForeignFieldMul) => self
                .foreign_field_mul_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::Xor16) => self
                .xor_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::Rot64) => self
                .rot_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Permutation(i) => Ok(self.s[i]),
            Coefficient(i) => Ok(self.coefficients[i]),
            LookupKindIndex(LookupPattern::Xor) => self
                .xor_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupKindIndex(LookupPattern::Lookup) => self
                .lookup_gate_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupKindIndex(LookupPattern::RangeCheck) => self
                .range_check_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupKindIndex(LookupPattern::ForeignFieldMul) => self
                .foreign_field_mul_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupRuntimeSelector => self
                .runtime_lookup_table_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(_) => Err(ExprError::MissingIndexEvaluation(col)),
        }
    }
}
