/// Provides generic environment traits that allow manipulating columns and
/// requesting lookups.
///
/// Every trait implies two categories of implementations:
/// constraint ones (that operate over expressions, building a
/// circuit), and witness ones (that operate over values, building
/// values for the circuit).
use crate::{columns::ColumnIndexer, logup::LookupTableID};
use ark_ff::PrimeField;

/// Environment capability for accessing and reading columns. This is necessary for
/// building constraints.
pub trait ColAccessCap<F: PrimeField, CIx: ColumnIndexer> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Neg<Output = Self::Variable>
        + From<u64>
        + std::fmt::Debug;

    /// Asserts that the value is zero.
    fn assert_zero(&mut self, cst: Self::Variable);

    /// Reads value from a column position.
    fn read_column(&self, ix: CIx) -> Self::Variable;

    /// Turns a constant value into a variable.
    fn constant(value: F) -> Self::Variable;
}

/// Environment capability similar to `ColAcessT` but for /also
/// writing/ columns. Used on the witness side.
pub trait ColWriteCap<F: PrimeField, CIx: ColumnIndexer>
where
    Self: ColAccessCap<F, CIx>,
{
    fn write_column(&mut self, ix: CIx, value: &Self::Variable);
}

/// Capability for invoking table lookups.
pub trait LookupCap<F: PrimeField, CIx: ColumnIndexer, LT: LookupTableID>
where
    Self: ColAccessCap<F, CIx>,
{
    fn lookup(&mut self, lookup_id: LT, value: &Self::Variable);
}
