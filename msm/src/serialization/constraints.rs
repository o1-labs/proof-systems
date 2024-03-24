use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use std::collections::BTreeMap;

use crate::{columns::Column, expr::E, serialization::N_INTERMEDIATE_LIMBS, N_LIMBS};

use super::Lookup;
use super::{interpreter::InterpreterEnv, LookupTable};
use crate::mvlookup::constraint_lookups;

pub struct Env<Fp> {
    /// An indexed set of constraints.
    /// The index can be used to differentiate the constraints used by different
    /// calls to the interpreter function, and let the callers ordered them for
    /// folding for instance.
    pub constraints: Vec<(usize, Expr<ConstantExpr<Fp>, Column>)>,
    pub constrain_index: usize,
    pub lookups: BTreeMap<LookupTable, Vec<Lookup<E<Fp>>>>,
}

impl<Fp: PrimeField> Env<Fp> {
    pub fn create() -> Self {
        Self {
            constraints: vec![],
            constrain_index: 0,
            lookups: BTreeMap::new(),
        }
    }
}

impl<F: PrimeField> InterpreterEnv<F> for Env<F> {
    type Position = Column;

    type Variable = E<F>;

    fn add_constraint(&mut self, cst: Self::Variable) {
        // FIXME: We should enforce that we add the same expression
        // Maybe we could have a digest of the expression
        let index = self.constrain_index;
        self.constraints.push((index, cst));
        self.constrain_index += 1;
    }

    fn copy(&mut self, _x: &Self::Variable, position: Self::Position) -> Self::Variable {
        // No-op in constraints, witness only
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    fn get_column_for_kimchi_limb(j: usize) -> Self::Position {
        assert!(j < 3);
        Column::X(j)
    }

    fn get_column_for_intermediate_limb(j: usize) -> Self::Position {
        assert!(j < N_INTERMEDIATE_LIMBS);
        Column::X(3 + N_LIMBS + j)
    }

    fn get_column_for_msm_limb(j: usize) -> Self::Position {
        assert!(j < N_LIMBS);
        Column::X(3 + j)
    }

    fn range_check15(&mut self, value: &Self::Variable) {
        self.add_lookup(LookupTable::RangeCheck15, value);
    }

    fn range_check4(&mut self, value: &Self::Variable) {
        self.add_lookup(LookupTable::RangeCheck4, value);
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
        position: Self::Position,
    ) -> Self::Variable {
        // No constraint added. It is supposed that the caller will constraint
        // later the returned variable and/or do a range check.
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }
}

impl<F: PrimeField> Env<F> {
    fn add_lookup(&mut self, table_id: LookupTable, value: &E<F>) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        let lookup = Lookup {
            table_id,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        };
        self.lookups.entry(table_id).or_default().push(lookup);
    }

    pub fn get_constraints(&self) -> Vec<E<F>> {
        let mut constraints: Vec<E<F>> = vec![];

        let relation_constraints: Vec<E<F>> = self
            .constraints
            .iter()
            .map(|(_, cst)| cst.clone())
            .collect();
        constraints.extend(relation_constraints);

        assert!(self.lookups[&LookupTable::RangeCheck15].len() == 17);
        assert!(self.lookups[&LookupTable::RangeCheck4].len() == 20);

        let _lookup_constraint = constraint_lookups(&self.lookups);
        // FIXME: LookupMultiplicity must still be correctly implemented in column_env.
        // Activate lookup constraints after by decommenting the following line
        // constraints.extend(_lookup_constraint);
        constraints
    }
}
