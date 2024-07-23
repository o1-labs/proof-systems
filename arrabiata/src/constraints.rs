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
use num_bigint::BigUint;
use o1_utils::FieldHelpers;

pub struct Env<Fp: Field> {
    pub poseidon_mds: Vec<Vec<Fp>>,
    pub idx_var: usize,
    pub idx_var_pi: usize,
    pub constraints: Vec<E<Fp>>,
}

impl<Fp: Field> Env<Fp> {
    pub fn new(poseidon_mds: Vec<Vec<Fp>>) -> Self {
        Self {
            poseidon_mds,
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

    /// Return the corresponding expression regarding the selected public input
    fn write_public_input(&mut self, col: Self::Position, _v: BigUint) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    }

    /// Return the corresponding expression regarding the selected column
    fn write_column(&mut self, col: Self::Position, _v: Self::Variable) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    }

    fn add_constraint(&mut self, constraint: Self::Variable) {
        let degree = constraint.degree(1, 0);
        debug!("Adding constraint of degree {degree}: {:}", constraint);
        assert!(degree <= MAX_DEGREE, "degree is too high: {}. The folding scheme used currently allows constraint up to degree {}", degree, MAX_DEGREE);
        self.constraints.push(constraint);
    }

    fn constrain_boolean(&mut self, x: Self::Variable) {
        let one_bui = BigUint::from(1_usize);
        let one = self.constant(one_bui);
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
        self.idx_var_pi = 0;
    }

    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn get_sixteen_bits_chunks_folding_combiner(
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
}
