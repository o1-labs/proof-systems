use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

use crate::mvlookup::combine_lookups;

use crate::{
    columns::{Column, ColumnIndexer},
    expr::{curr_cell, next_cell, E},
    serialization::column::SerializationColumn,
    MVLookupTableID as _,
};

use super::{interpreter::InterpreterEnv, Lookup, LookupTable};

pub struct Env<Fp> {
    /// An indexed set of constraints.
    /// The index can be used to differentiate the constraints used by different
    /// calls to the interpreter function, and let the callers ordered them for
    /// folding for instance.
    pub constraints: Vec<(usize, Expr<ConstantExpr<Fp>, Column>)>,
    pub constrain_index: usize,
    pub rangecheck4_lookups: Vec<Lookup<E<Fp>>>,
    pub rangecheck15_lookups: Vec<Lookup<E<Fp>>>,
}

impl<Fp: PrimeField> Env<Fp> {
    pub fn create() -> Self {
        Self {
            constraints: vec![],
            constrain_index: 0,
            rangecheck4_lookups: vec![],
            rangecheck15_lookups: vec![],
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

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let y = Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }));
        self.add_constraint(y.clone() - x.clone());
        y
    }

    fn read_column(&self, position: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    fn get_column(pos: SerializationColumn) -> Self::Position {
        pos.ix_to_column()
    }

    fn range_check_abs15bit(&mut self, _value: &Self::Variable) {
        // FIXME unimplemented
    }

    fn range_check_ff_highest<Ff: PrimeField>(&mut self, _value: &Self::Variable) {
        // FIXME unmplemented
    }

    fn range_check_abs4bit(&mut self, _value: &Self::Variable) {
        // FIXME unimplemented
    }

    fn range_check15(&mut self, value: &Self::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        self.rangecheck15_lookups.push(Lookup {
            table_id: LookupTable::RangeCheck15,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        })
    }

    fn range_check4(&mut self, value: &Self::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        self.rangecheck4_lookups.push(Lookup {
            table_id: LookupTable::RangeCheck4,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        })
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

impl<Fp: PrimeField> Env<Fp> {
    #[allow(dead_code)]
    // FIXME: not mut
    fn constrain_lookups(&mut self) -> Vec<E<Fp>> {
        assert_eq!(self.rangecheck4_lookups.len(), 20);
        assert_eq!(self.rangecheck15_lookups.len(), 17);

        {
            let rc4_t_lookup = Lookup {
                table_id: LookupTable::RangeCheck4,
                numerator: curr_cell(Column::LookupMultiplicity(
                    LookupTable::RangeCheck4.to_u32(),
                )),
                value: vec![curr_cell(Column::LookupFixedTable(
                    LookupTable::RangeCheck4.to_u32(),
                ))],
            };
            self.rangecheck4_lookups.push(rc4_t_lookup);
        }

        {
            let rc15_t_lookup = Lookup {
                table_id: LookupTable::RangeCheck15,
                numerator: curr_cell(Column::LookupMultiplicity(
                    LookupTable::RangeCheck15.to_u32(),
                )),
                value: vec![curr_cell(Column::LookupFixedTable(
                    LookupTable::RangeCheck15.to_u32(),
                ))],
            };
            self.rangecheck15_lookups.push(rc15_t_lookup);
        }

        // This can be generalized for any table. We can have a hashmap or an
        // array of lookups
        // Computing individual "boat"
        let mut constraints = vec![];
        let mut idx = 0;
        for chunk in self.rangecheck4_lookups.chunks(6) {
            constraints.push(combine_lookups(
                Column::LookupPartialSum(idx),
                chunk.to_vec(),
            ));
            idx += 1;
        }

        for chunk in self.rangecheck15_lookups.chunks(6) {
            constraints.push(combine_lookups(
                Column::LookupPartialSum(idx),
                chunk.to_vec(),
            ));
            idx += 1;
        }

        // Generic code over the partial sum
        // Compute \phi(\omega X) - \phi(X) - \sum_{i = 1}^{N} h_i(X)
        {
            let constraint =
                next_cell(Column::LookupAggregation) - curr_cell(Column::LookupAggregation);
            let constraint = (0..idx).fold(constraint, |acc, i| {
                acc - curr_cell(Column::LookupPartialSum(i))
            });
            constraints.push(constraint);
        }
        constraints
    }
}
