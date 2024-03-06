use crate::ffa::columns::FFAColumnIndexer;
use ark_ff::PrimeField;

pub trait FFAInterpreterEnv<Fp: PrimeField> {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn add_constraint(&mut self, cst: Self::Variable);

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn constant(value: Fp) -> Self::Variable;

    fn get_column(ix: FFAColumnIndexer) -> Self::Position;
}
