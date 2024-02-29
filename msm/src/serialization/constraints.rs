use ark_ff::Field;
use kimchi::circuits::expr::{ConstantExpr, Expr};

use crate::columns::Column;

use super::interpreter::InterpreterEnv;

pub struct Env<Fp> {
    pub constraints: Vec<Expr<ConstantExpr<Fp>, Column>>,
}

impl<F: Field> InterpreterEnv for Env<F> {
    type Position = Column;

    type Variable = Expr<ConstantExpr<F>, Column>;

    fn add_constraint(&mut self, cst: Self::Variable) {
        self.constraints.push(cst)
    }

    fn copy(&mut self, _x: &Self::Variable, _position: Self::Position) -> Self::Variable {
        unimplemented!()
    }

    fn get_column_for_kimchi_limb(_j: usize) -> Self::Position {
        unimplemented!()
    }

    fn get_column_for_intermediate_limb(_j: usize) -> Self::Position {
        unimplemented!()
    }

    fn get_column_for_msm_limb(_j: usize) -> Self::Position {
        unimplemented!()
    }

    fn constant(_value: u128) -> Self::Variable {
        unimplemented!()
    }

    /// Extract the bits from the variable `x` between `highest_bit` and `lowest_bit`, and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        _position: Self::Position,
    ) -> Self::Variable {
        unimplemented!()
    }
}
