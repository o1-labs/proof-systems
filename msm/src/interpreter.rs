use ark_ff::PrimeField;

use crate::columns::{Column, ColumnIndexer};

/// Attempt to define a generic interpreter.
/// It is not used yet.
pub trait InterpreterEnv<ColumnIx: ColumnIndexer, Fp: PrimeField> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn add_constraint(&mut self, cst: Self::Variable);

    fn copy(&mut self, x: &Self::Variable, position: Column) -> Self::Variable;

    fn get_column(ix: ColumnIx) -> Column {
        ix.ix_to_column()
    }

    /// Read the value in the position `ix`
    fn read_column(ix: ColumnIx) -> Self::Variable;

    fn constant(value: Fp) -> Self::Variable;
}
