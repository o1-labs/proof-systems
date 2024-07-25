use super::{columns::Column, interpreter::InterpreterEnv};
use crate::{
    columns::E, interpreter::ECAdditionSide, MAX_DEGREE, NUMBER_OF_COLUMNS, NUMBER_OF_PUBLIC_INPUTS,
};
use ark_ff::{Field, PrimeField};
use kimchi::circuits::{
    expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};
use log::debug;
use num_bigint::BigInt;
use o1_utils::FieldHelpers;

pub struct Env<Fp: Field> {
    pub poseidon_mds: Vec<Vec<Fp>>,
    /// The parameter a is the coefficients of the elliptic curve in affine
    /// coordinates.
    // FIXME: this is ugly. Let use the curve as a parameter. Only lazy for now.
    pub a: BigInt,
    pub idx_var: usize,
    pub idx_var_pi: usize,
    pub constraints: Vec<E<Fp>>,
}

impl<Fp: PrimeField> Env<Fp> {
    pub fn new(poseidon_mds: Vec<Vec<Fp>>, a: BigInt) -> Self {
        // This check might not be useful
        assert!(a < Fp::modulus_biguint().into(), "a is too large");
        Self {
            poseidon_mds,
            a,
            idx_var: 0,
            idx_var_pi: 0,
            constraints: Vec::new(),
        }
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

    fn allocate_public_input(&mut self) -> Self::Position {
        assert!(self.idx_var_pi < NUMBER_OF_PUBLIC_INPUTS, "Maximum number of public inputs reached ({NUMBER_OF_PUBLIC_INPUTS}), increase the number of public inputs");
        let pos = Column::PublicInput(self.idx_var_pi);
        self.idx_var_pi += 1;
        pos
    }

    fn constant(&self, value: BigInt) -> Self::Variable {
        let v = value.to_biguint().unwrap();
        let v = Fp::from_biguint(&v).unwrap();
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    /// Return the corresponding expression regarding the selected public input
    fn write_public_input(&mut self, col: Self::Position, _v: BigInt) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    }

    /// Return the corresponding expression regarding the selected column
    fn write_column(&mut self, col: Self::Position, v: Self::Variable) -> Self::Variable {
        let res = Expr::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }));
        self.assert_equal(res.clone(), v);
        res
    }

    fn add_constraint(&mut self, constraint: Self::Variable) {
        let degree = constraint.degree(1, 0);
        debug!("Adding constraint of degree {degree}: {:}", constraint);
        assert!(degree <= MAX_DEGREE, "degree is too high: {}. The folding scheme used currently allows constraint up to degree {}", degree, MAX_DEGREE);
        self.constraints.push(constraint);
    }

    fn constrain_boolean(&mut self, x: Self::Variable) {
        let one = self.one();
        let c = x.clone() * (x.clone() - one);
        self.constraints.push(c)
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
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
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
        self.idx_var_pi = 0;
    }

    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn read_sixteen_bits_chunks_folding_combiner(
        &mut self,
        pos: Self::Position,
        _i: u32,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn read_bit_of_folding_combiner(
        &mut self,
        pos: Self::Position,
        _i: u32,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    fn get_poseidon_state(&mut self, pos: Self::Position, _i: usize) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    // Witness-only
    fn update_poseidon_state(&mut self, _x: Self::Variable, _i: usize) {}

    fn get_poseidon_round_constant(
        &mut self,
        pos: Self::Position,
        _round: usize,
        _i: usize,
    ) -> Self::Variable {
        match pos {
            Column::PublicInput(_) => (),
            _ => panic!("Only public inputs can be used as round constants"),
        };
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable {
        let v = self.poseidon_mds[i][j];
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    fn load_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        _i: usize,
        _side: ECAdditionSide,
    ) -> (Self::Variable, Self::Variable) {
        let x = Expr::Atom(ExprInner::Cell(Variable {
            col: pos_x,
            row: CurrOrNext::Curr,
        }));
        let y = Expr::Atom(ExprInner::Cell(Variable {
            col: pos_y,
            row: CurrOrNext::Curr,
        }));
        (x, y)
    }

    /// Inverse of a variable
    ///
    /// # Safety
    ///
    /// Zero is not allowed as an input.
    unsafe fn inverse(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable {
        let v = Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }));
        let res = v.clone() * x.clone();
        self.assert_equal(res.clone(), self.one());
        v
    }

    // FIXME: no constraint added for now.
    fn is_same_ec_point(
        &mut self,
        pos: Self::Position,
        _x1: Self::Variable,
        _y1: Self::Variable,
        _x2: Self::Variable,
        _y2: Self::Variable,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    fn one(&self) -> Self::Variable {
        self.constant(BigInt::from(1_usize))
    }

    fn compute_lambda(
        &mut self,
        pos: Self::Position,
        is_same_point: Self::Variable,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable {
        let lambda = Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }));
        let lhs = lambda.clone() * (x1.clone() - x2.clone()) - (y1.clone() - y2.clone());
        let rhs = {
            let x1_square = x1.clone() * x1.clone();
            let two_x1_square = x1_square.clone() + x1_square.clone();
            let three_x1_square = two_x1_square.clone() + x1_square.clone();
            let two_y1 = y1.clone() + y1.clone();
            lambda.clone() * two_y1 - (three_x1_square + self.constant(self.a.clone()))
        };
        let res = is_same_point.clone() * lhs + (self.one() - is_same_point.clone()) * rhs;
        self.assert_zero(res);
        lambda
    }
}
