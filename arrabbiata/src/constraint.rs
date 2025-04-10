use super::{column::Column, interpreter::InterpreterEnv};
use crate::{
    column::{Gadget, E},
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    interpreter::{self, Instruction, Side},
    MAX_DEGREE, NUMBER_OF_COLUMNS,
};

use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};
use log::debug;
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;
use o1_utils::FieldHelpers;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Env<C: ArrabbiataCurve>
where
    C::BaseField: PrimeField,
{
    /// The parameter a is the coefficients of the elliptic curve in affine
    /// coordinates.
    pub a: BigInt,
    pub idx_var: usize,
    pub idx_var_next_row: usize,
    pub constraints: Vec<E<C::ScalarField>>,
}

impl<C: ArrabbiataCurve> Env<C>
where
    C::BaseField: PrimeField,
{
    pub fn new() -> Self {
        // This check might not be useful
        let a: C::BaseField = C::get_curve_params().0;
        let a: BigInt = a.to_biguint().into();
        assert!(
            a < C::ScalarField::modulus_biguint().into(),
            "a is too large"
        );
        Self {
            a,
            idx_var: 0,
            idx_var_next_row: 0,
            constraints: Vec::new(),
        }
    }
}

/// An environment to build constraints.
/// The constraint environment is mostly useful when we want to perform a Nova
/// proof.
/// The constraint environment must be instantiated only once, at the last step
/// of the computation.
impl<C: ArrabbiataCurve> InterpreterEnv for Env<C>
where
    C::BaseField: PrimeField,
{
    type Position = (Column, CurrOrNext);

    type Variable = E<C::ScalarField>;

    fn allocate(&mut self) -> Self::Position {
        assert!(self.idx_var < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        (pos, CurrOrNext::Curr)
    }

    fn allocate_next_row(&mut self) -> Self::Position {
        assert!(self.idx_var_next_row < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        let pos = Column::X(self.idx_var_next_row);
        self.idx_var_next_row += 1;
        (pos, CurrOrNext::Next)
    }

    fn read_position(&self, pos: Self::Position) -> Self::Variable {
        let (col, row) = pos;
        Expr::Atom(ExprInner::Cell(Variable { col, row }))
    }

    fn constant(&self, value: BigInt) -> Self::Variable {
        let v = value.to_biguint().unwrap();
        let v = C::ScalarField::from_biguint(&v).unwrap();
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    /// Return the corresponding expression regarding the selected column
    fn write_column(&mut self, pos: Self::Position, v: Self::Variable) -> Self::Variable {
        let (col, row) = pos;
        let res = Expr::Atom(ExprInner::Cell(Variable { col, row }));
        self.assert_equal(res.clone(), v);
        res
    }

    fn add_constraint(&mut self, constraint: Self::Variable) {
        let degree = constraint.degree(1, 0);
        debug!("Adding constraint of degree {degree}: {:}", constraint);
        assert!(degree <= MAX_DEGREE.try_into().unwrap(), "degree is too high: {}. The folding scheme used currently allows constraint up to degree {}", degree, MAX_DEGREE);
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
        pos: Self::Position,
    ) -> Self::Variable {
        self.read_position(pos)
    }

    fn square(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable {
        let v = self.read_position(pos);
        let x = x.square();
        self.add_constraint(x - v.clone());
        v
    }

    // This is witness-only. We simply return the corresponding expression to
    // use later in constraints
    fn fetch_input(&mut self, pos: Self::Position) -> Self::Variable {
        self.read_position(pos)
    }

    fn reset(&mut self) {
        self.idx_var = 0;
        self.idx_var_next_row = 0;
        self.constraints.clear();
    }

    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        self.read_position(pos)
    }

    fn load_poseidon_state(&mut self, pos: Self::Position, _i: usize) -> Self::Variable {
        self.read_position(pos)
    }

    // Witness-only
    unsafe fn save_poseidon_state(&mut self, _x: Self::Variable, _i: usize) {}

    fn get_poseidon_round_constant(&self, round: usize, i: usize) -> Self::Variable {
        let cst = C::sponge_params().round_constants[round][i];
        let cst_inner = Operations::from(Literal(cst));
        Self::Variable::constant(cst_inner)
    }

    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable {
        let v = C::sponge_params().mds[i][j];
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    unsafe fn fetch_value_to_absorb(&mut self, pos: Self::Position) -> Self::Variable {
        self.read_position(pos)
    }

    unsafe fn load_temporary_accumulators(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        _side: Side,
    ) -> (Self::Variable, Self::Variable) {
        let x = self.read_position(pos_x);
        let y = self.read_position(pos_y);
        (x, y)
    }

    // witness only
    unsafe fn save_temporary_accumulators(
        &mut self,
        _x: Self::Variable,
        _y: Self::Variable,
        _side: Side,
    ) {
    }

    /// Inverse of a variable
    ///
    /// # Safety
    ///
    /// Zero is not allowed as an input.
    unsafe fn inverse(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable {
        let v = self.read_position(pos);
        let res = v.clone() * x.clone();
        self.assert_equal(res.clone(), self.one());
        v
    }

    unsafe fn is_same_ec_point(
        &mut self,
        pos: Self::Position,
        _x1: Self::Variable,
        _y1: Self::Variable,
        _x2: Self::Variable,
        _y2: Self::Variable,
    ) -> Self::Variable {
        self.read_position(pos)
    }

    fn zero(&self) -> Self::Variable {
        self.constant(BigInt::from(0_usize))
    }

    fn one(&self) -> Self::Variable {
        self.constant(BigInt::from(1_usize))
    }

    /// Double the elliptic curve point given by the affine coordinates
    /// `(x1, y1)` and save the result in the registers `pos_x` and `pos_y`.
    fn double_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
    ) -> (Self::Variable, Self::Variable) {
        let lambda = {
            let pos = self.allocate();
            self.read_position(pos)
        };
        let x3 = self.read_position(pos_x);
        let y3 = self.read_position(pos_y);

        // λ 2y1 = 3x1^2 + a
        let x1_square = x1.clone() * x1.clone();
        let two_x1_square = x1_square.clone() + x1_square.clone();
        let three_x1_square = two_x1_square.clone() + x1_square.clone();
        let two_y1 = y1.clone() + y1.clone();
        let res = lambda.clone() * two_y1 - (three_x1_square + self.constant(self.a.clone()));
        self.assert_zero(res);
        // x3 = λ^2 - 2 x1
        self.assert_equal(
            x3.clone(),
            lambda.clone() * lambda.clone() - x1.clone() - x1.clone(),
        );
        // y3 = λ(x1 - x3) - y1
        self.assert_equal(
            y3.clone(),
            lambda.clone() * (x1.clone() - x3.clone()) - y1.clone(),
        );
        (x3, y3.clone())
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
        let lambda = self.read_position(pos);
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

impl<C: ArrabbiataCurve> Env<C>
where
    C::BaseField: PrimeField,
{
    /// Get all the constraints for the verifier circuit, only.
    ///
    /// The following gadgets are used in the verifier circuit:
    /// - [Instruction::PoseidonFullRound] and
    ///   [Instruction::PoseidonSpongeAbsorb] to verify the challenges and the
    ///   public IO.
    /// - [Instruction::EllipticCurveScaling] and
    ///   [Instruction::EllipticCurveAddition] to accumulate the commitments
    // FIXME: the verifier circuit might not be complete, yet. For instance, we might
    // need to accumulate the challenges and add a row to verify the output of
    // the computation of the challenges.
    // FIXME: add a test checking that whatever the value given in parameter of
    // the gadget, the constraints are the same
    pub fn get_all_constraints_for_verifier(&self) -> Vec<E<C::ScalarField>> {
        // Copying the instance we got in parameter, and making it mutable to
        // avoid modifying the original instance.
        let mut env = self.clone();
        // Resetting before running anything
        env.reset();

        let mut constraints = vec![];

        // Poseidon constraints
        (0..PlonkSpongeConstants::PERM_ROUNDS_FULL / 12).for_each(|i| {
            interpreter::run_ivc(&mut env, Instruction::PoseidonFullRound(5 * i));
            constraints.extend(env.constraints.clone());
            env.reset();
        });

        interpreter::run_ivc(&mut env, Instruction::PoseidonSpongeAbsorb);
        constraints.extend(env.constraints.clone());
        env.reset();

        // EC scaling
        // The constraints are the same whatever the value given in parameter,
        // therefore picking 0, 0
        interpreter::run_ivc(&mut env, Instruction::EllipticCurveScaling(0, 0));
        constraints.extend(env.constraints.clone());
        env.reset();

        // EC addition
        // The constraints are the same whatever the value given in parameter,
        // therefore picking 0
        interpreter::run_ivc(&mut env, Instruction::EllipticCurveAddition(0));
        constraints.extend(env.constraints.clone());
        env.reset();

        constraints
    }

    /// Get all the constraints for the verifier circuit and the application.
    // FIXME: the application should be given as an argument to handle Rust
    // zkApp. It is only for the PoC.
    // FIXME: the selectors are not added for now.
    pub fn get_all_constraints(&self) -> Vec<E<C::ScalarField>> {
        let mut constraints = self.get_all_constraints_for_verifier();

        // Copying the instance we got in parameter, and making it mutable to
        // avoid modifying the original instance.
        let mut env = self.clone();
        // Resetting before running anything
        env.reset();

        // Get the constraints for the application
        interpreter::run_app(&mut env);
        constraints.extend(env.constraints.clone());

        constraints
    }

    pub fn get_all_constraints_indexed_by_gadget(&self) -> HashMap<Gadget, Vec<E<C::ScalarField>>> {
        let mut hashmap = HashMap::new();
        let mut env = self.clone();

        // Poseidon constraints
        (0..PlonkSpongeConstants::PERM_ROUNDS_FULL / 12).for_each(|i| {
            interpreter::run_ivc(&mut env, Instruction::PoseidonFullRound(5 * i));
            hashmap.insert(Gadget::PoseidonFullRound(5 * i), env.constraints.clone());
            env.reset();
        });

        interpreter::run_ivc(&mut env, Instruction::PoseidonSpongeAbsorb);
        hashmap.insert(Gadget::PoseidonSpongeAbsorb, env.constraints.clone());
        env.reset();

        // EC scaling
        // The constraints are the same whatever the value given in parameter,
        // therefore picking 0, 0
        interpreter::run_ivc(&mut env, Instruction::EllipticCurveScaling(0, 0));
        hashmap.insert(Gadget::EllipticCurveScaling, env.constraints.clone());
        env.reset();

        // EC addition
        // The constraints are the same whatever the value given in parameter,
        // therefore picking 0
        interpreter::run_ivc(&mut env, Instruction::EllipticCurveAddition(0));
        hashmap.insert(Gadget::EllipticCurveAddition, env.constraints.clone());
        env.reset();

        interpreter::run_app(&mut env);
        hashmap.insert(Gadget::App, env.constraints.clone());
        env.reset();

        hashmap
    }
}

impl<C: ArrabbiataCurve> Default for Env<C>
where
    C::BaseField: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}
