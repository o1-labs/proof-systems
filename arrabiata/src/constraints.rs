use super::{columns::Column, interpreter::InterpreterEnv};
use crate::{columns::E, MAX_DEGREE};
use ark_ff::{Field, PrimeField};
use kimchi::circuits::{
    expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};
use num_bigint::BigUint;
use o1_utils::FieldHelpers;

pub struct Env<Fp: Field> {
    pub idx_var: usize,
    pub constraints: Vec<E<Fp>>,
}

impl<Fp: Field> Env<Fp> {
    pub fn new() -> Self {
        Self {
            idx_var: 0,
            constraints: Vec::new(),
        }
    }
}

impl<Fp: Field> Default for Env<Fp> {
    fn default() -> Self {
        Self::new()
    }
}

/// An environment to build constraints.
/// The constraint environment is mostly useful when we want to perform a Nova
/// proof.
/// The constraint environment must be instantiated only once, at the last step
/// of the computation.
impl<Fp: PrimeField> InterpreterEnv for Env<Fp> {
    type Position = Column;

    type Variable = E<Fp>;

    fn allocate(&mut self) -> Self::Position {
        assert!(self.idx_var < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        pos
    }

    fn variable(&self, column: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: column,
            row: CurrOrNext::Curr,
        }))
    }

    fn constant(&self, value: BigUint) -> Self::Variable {
        let v = Fp::from_biguint(&value).unwrap();
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    fn add_constraint(&mut self, constraint: Self::Variable) {
        let degree = constraint.degree(1, 0);
        assert!(degree <= MAX_DEGREE, "degree is too high: {}. The folding scheme used currently allows constraint up to degree {}", degree, MAX_DEGREE);
        self.constraints.push(constraint);
    }

    fn assert_zero(&mut self, x: Self::Variable) {
        self.add_constraint(x);
    }

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        self.add_constraint(x - y);
    }

    unsafe fn bitmask_be(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    // FIXME
    fn range_check16(&mut self, _x: Self::Position) {}

    fn square(&mut self, col: Self::Position, x: Self::Variable) -> Self::Variable {
        let v = Expr::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }));
        let x = x.square();
        self.add_constraint(x - v.clone());
        v
    }

    // This is witness-only. We simply return the corresponding expression to
    // use later in constraints
    fn fetch_input(&mut self, res: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: res,
            row: CurrOrNext::Curr,
        }))
    }

    fn reset(&mut self) {
        self.idx_var = 0;
    }

    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }
}
