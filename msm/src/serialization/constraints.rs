use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use std::collections::BTreeMap;

use crate::{
    columns::{Column, ColumnIndexer},
    expr::E,
    logup::{constraint_lookups, Logup, LookupTableID},
    serialization::interpreter::InterpreterEnv,
};

pub struct ConstraintBuilderEnv<F: PrimeField, LT: LookupTableID> {
    /// An indexed set of constraints.
    /// The index can be used to differentiate the constraints used by different
    /// calls to the interpreter function, and let the callers ordered them for
    /// folding for instance.
    pub constraints: Vec<(usize, Expr<ConstantExpr<F>, Column>)>,
    pub constrain_index: usize,
    pub lookups: BTreeMap<LT, Vec<Logup<E<F>, LT>>>,
}

impl<F: PrimeField, LT: LookupTableID> ConstraintBuilderEnv<F, LT> {
    pub fn create() -> Self {
        Self {
            constraints: vec![],
            constrain_index: 0,
            lookups: BTreeMap::new(),
        }
    }
}

impl<F: PrimeField, CIx: ColumnIndexer, LT: LookupTableID> InterpreterEnv<F, CIx, LT>
    for ConstraintBuilderEnv<F, LT>
{
    type Variable = E<F>;

    fn assert_zero(&mut self, cst: Self::Variable) {
        // FIXME: We should enforce that we add the same expression
        // Maybe we could have a digest of the expression
        let index = self.constrain_index;
        self.constraints.push((index, cst));
        self.constrain_index += 1;
    }

    fn copy(&mut self, x: &Self::Variable, position: CIx) -> Self::Variable {
        let y = Expr::Atom(ExprInner::Cell(Variable {
            col: position.to_column(),
            row: CurrOrNext::Curr,
        }));
        let diff: Self::Variable = y.clone() - x.clone();
        <Self as InterpreterEnv<F, CIx, LT>>::assert_zero(self, diff);
        y
    }

    fn read_column(&self, position: CIx) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position.to_column(),
            row: CurrOrNext::Curr,
        }))
    }

    fn lookup(&mut self, table_id: LT, value: &Self::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        let lookup = Logup {
            table_id,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        };
        self.lookups.entry(table_id).or_default().push(lookup);
    }

    fn constant(value: F) -> Self::Variable {
        let cst_expr_inner = ConstantExpr::from(ConstantTerm::Literal(value));
        Expr::Atom(ExprInner::Constant(cst_expr_inner))
    }

    /// Extract the bits from the variable `x` between `highest_bit` (excluded)
    /// and `lowest_bit` (included), and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: CIx,
    ) -> Self::Variable {
        // No constraint added. It is supposed that the caller will constraint
        // later the returned variable and/or do a range check.
        Expr::Atom(ExprInner::Cell(Variable {
            col: position.to_column(),
            row: CurrOrNext::Curr,
        }))
    }
}

impl<F: PrimeField, LT: LookupTableID> ConstraintBuilderEnv<F, LT> {
    pub fn get_constraints(&self) -> Vec<E<F>> {
        let mut constraints: Vec<E<F>> = vec![];

        let relation_constraints: Vec<E<F>> = self
            .constraints
            .iter()
            .map(|(_, cst)| cst.clone())
            .collect();
        constraints.extend(relation_constraints);

        let lookup_constraint = constraint_lookups(&self.lookups);
        constraints.extend(lookup_constraint);
        constraints
    }
}
