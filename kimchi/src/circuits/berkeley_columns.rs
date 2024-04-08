use crate::{
    circuits::{
        domains::EvaluationDomains,
        expr::{CacheId, ColumnEvaluations, ConstantExpr, ConstantTerm, Expr, ExprError},
        gate::{CurrOrNext, GateType},
        lookup::{index::LookupSelectors, lookups::LookupPattern},
    },
    proof::{PointEvaluations, ProofEvaluations},
};
use serde::{Deserialize, Serialize};

use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};

use crate::circuits::expr::{Challenges, ColumnEnvironment, Constants, Domain, FormattedOutput};

use crate::circuits::wires::COLUMNS;

use std::collections::HashMap;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// A type representing one of the polynomials involved in the PLONK IOP, use in
/// the Berkeley hardfork.
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

impl FormattedOutput for Column {
    fn is_alpha(&self) -> bool {
        // FIXME. Unused at the moment
        unimplemented!()
    }

    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        // FIXME. Unused at the moment
        unimplemented!()
    }

    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
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

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
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

impl<'a, F: FftField> ColumnEnvironment<'a, F> for Environment<'a, F> {
    type Column = Column;

    fn get_column(&self, col: &Self::Column) -> Option<&'a Evaluations<F, D<F>>> {
        use Column::*;
        let lookup = self.lookup.as_ref();
        match col {
            Witness(i) => Some(&self.witness[*i]),
            Coefficient(i) => Some(&self.coefficient[*i]),
            Z => Some(self.z),
            LookupKindIndex(i) => lookup.and_then(|l| l.selectors[*i].as_ref()),
            LookupSorted(i) => lookup.map(|l| &l.sorted[*i]),
            LookupAggreg => lookup.map(|l| l.aggreg),
            LookupTable => lookup.map(|l| l.table),
            LookupRuntimeSelector => lookup.and_then(|l| l.runtime_selector),
            LookupRuntimeTable => lookup.and_then(|l| l.runtime_table),
            Index(t) => match self.index.get(t) {
                None => None,
                Some(e) => Some(e),
            },
            Permutation(_) => None,
        }
    }

    fn get_domain(&self, d: Domain) -> D<F> {
        match d {
            Domain::D1 => self.domain.d1,
            Domain::D2 => self.domain.d2,
            Domain::D4 => self.domain.d4,
            Domain::D8 => self.domain.d8,
        }
    }

    fn column_domain(&self, col: &Self::Column) -> Domain {
        match *col {
            Self::Column::Index(GateType::Generic) => Domain::D4,
            Self::Column::Index(GateType::CompleteAdd) => Domain::D4,
            _ => Domain::D8,
        }
    }

    fn get_constants(&self) -> &Constants<F> {
        &self.constants
    }

    fn get_challenges(&self) -> &Challenges<F> {
        &self.challenges
    }

    fn vanishes_on_zero_knowledge_and_previous_rows(&self) -> &'a Evaluations<F, D<F>> {
        self.vanishes_on_zero_knowledge_and_previous_rows
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}

/// The polynomials specific to the lookup argument.
///
/// All are evaluations over the D8 domain
pub struct LookupEnvironment<'a, F: FftField> {
    /// The sorted lookup table polynomials.
    pub sorted: &'a Vec<Evaluations<F, D<F>>>,
    /// The lookup aggregation polynomials.
    pub aggreg: &'a Evaluations<F, D<F>>,
    /// The lookup-type selector polynomials.
    pub selectors: &'a LookupSelectors<Evaluations<F, D<F>>>,
    /// The evaluations of the combined lookup table polynomial.
    pub table: &'a Evaluations<F, D<F>>,
    /// The evaluations of the optional runtime selector polynomial.
    pub runtime_selector: Option<&'a Evaluations<F, D<F>>>,
    /// The evaluations of the optional runtime table.
    pub runtime_table: Option<&'a Evaluations<F, D<F>>>,
}

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
///
/// All are evaluations.
pub struct Environment<'a, F: FftField> {
    /// The witness column polynomials
    pub witness: &'a [Evaluations<F, D<F>>; COLUMNS],
    /// The coefficient column polynomials
    pub coefficient: &'a [Evaluations<F, D<F>>; COLUMNS],
    /// The polynomial that vanishes on the zero-knowledge rows and the row before.
    pub vanishes_on_zero_knowledge_and_previous_rows: &'a Evaluations<F, D<F>>,
    /// The permutation aggregation polynomial.
    pub z: &'a Evaluations<F, D<F>>,
    /// The index selector polynomials.
    pub index: HashMap<GateType, &'a Evaluations<F, D<F>>>,
    /// The value `prod_{j != 1} (1 - omega^j)`, used for efficiently
    /// computing the evaluations of the unnormalized Lagrange basis polynomials.
    pub l0_1: F,
    /// Constant values required
    pub constants: Constants<F>,
    /// Challenges from the IOP.
    pub challenges: Challenges<F>,
    /// The domains used in the PLONK argument.
    pub domain: EvaluationDomains<F>,
    /// Lookup specific polynomials
    pub lookup: Option<LookupEnvironment<'a, F>>,
}

//
// Helpers
//

/// An alias for the intended usage of the expression type in constructing constraints.
pub type E<F> = Expr<ConstantExpr<F>, Column>;

/// Convenience function to create a constant as [Expr].
pub fn constant<F>(x: F) -> E<F> {
    ConstantTerm::Literal(x).into()
}

/// Helper function to quickly create an expression for a witness.
pub fn witness<F>(i: usize, row: CurrOrNext) -> E<F> {
    E::<F>::cell(Column::Witness(i), row)
}

/// Same as [witness] but for the current row.
pub fn witness_curr<F>(i: usize) -> E<F> {
    witness(i, CurrOrNext::Curr)
}

/// Same as [witness] but for the next row.
pub fn witness_next<F>(i: usize) -> E<F> {
    witness(i, CurrOrNext::Next)
}

/// Handy function to quickly create an expression for a gate.
pub fn index<F>(g: GateType) -> E<F> {
    E::<F>::cell(Column::Index(g), CurrOrNext::Curr)
}

pub fn coeff<F>(i: usize) -> E<F> {
    E::<F>::cell(Column::Coefficient(i), CurrOrNext::Curr)
}
