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
pub trait ColAccessCap<F: PrimeField, CIx: ColumnIndexer<usize>> {
    // NB: 'static here means that `Variable` does not contain any
    // references with a lifetime less than 'static. Which is true in
    // our case. Necessary for `set_assert_mapper`
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Neg<Output = Self::Variable>
        + From<u64>
        + std::fmt::Debug
        + 'static;

    /// Asserts that the value is zero.
    fn assert_zero(&mut self, cst: Self::Variable);

    /// Sets an assert predicate `f(X)` such that when assert_zero is
    /// called on x, it will actually perform `assert_zero(f(x))`.
    fn set_assert_mapper(&mut self, mapper: Box<dyn Fn(Self::Variable) -> Self::Variable>);

    /// Reads value from a column position.
    fn read_column(&self, col: CIx) -> Self::Variable;

    /// Turns a constant value into a variable.
    fn constant(value: F) -> Self::Variable;
}

/// Environment capability similar to `ColAccessCap` but for /also
/// writing/ columns. Used on the witness side.
pub trait ColWriteCap<F: PrimeField, CIx: ColumnIndexer<usize>>
where
    Self: ColAccessCap<F, CIx>,
{
    fn write_column(&mut self, col: CIx, value: &Self::Variable);
}

/// Capability for invoking table lookups.
pub trait LookupCap<F: PrimeField, CIx: ColumnIndexer<usize>, LT: LookupTableID>
where
    Self: ColAccessCap<F, CIx>,
{
    /// Look up (read) value from a lookup table.
    fn lookup(&mut self, lookup_id: LT, value: Vec<Self::Variable>);

    /// Write a value into a runtime table. Panics if called on a fixed table.
    fn lookup_runtime_write(&mut self, lookup_id: LT, value: Vec<Self::Variable>);
}

/// Capability for reading and moving forward in a multirow fashion.
/// Holds a "current" row that can be moved forward with `next_row`.
/// The `ColWriteCap` and `ColAccessCap` reason in terms of current
/// row. The two other methods can be used to read/write previous.
pub trait MultiRowReadCap<F: PrimeField, CIx: ColumnIndexer<usize>>
where
    Self: ColWriteCap<F, CIx>,
{
    /// Read value from a (row,column) position.
    fn read_row_column(&mut self, row: usize, col: CIx) -> Self::Variable;

    /// Progresses to the next row.
    fn next_row(&mut self);

    /// Returns the current row.
    fn curr_row(&self) -> usize;
}

// TODO this trait is very powerful. It basically abstract
// WitnessBuilderEnv (and other, similar environments). Nothing
// similar can be implemented for constraint building envs.
//
// Where possible, do your computation over Variable or directly via
// F-typed inputs to a function.
/// A direct field access capability modelling an abstract witness
/// builder. Not for constraint building.
pub trait DirectWitnessCap<F: PrimeField, CIx: ColumnIndexer<usize>>
where
    Self: MultiRowReadCap<F, CIx>,
{
    /// Convert an abstract variable to a field element! Inverse of Env::constant().
    fn variable_to_field(value: Self::Variable) -> F;
}

////////////////////////////////////////////////////////////////////////////
// Hybrid capabilities
////////////////////////////////////////////////////////////////////////////

/// Capability for computing arithmetic functions and enforcing
/// constraints simultaneously.
///
/// The "hybrid" in the name of the trait (and other traits here)
/// means "maybe".
///
/// That is, it allows computations which /might be/ no-ops (even
/// partially) in the constraint builder case. For example, "hcopy",
/// despite its name, does not do any "write", so hcopy !=>
/// write_column.
pub trait HybridCopyCap<F: PrimeField, CIx: ColumnIndexer<usize>>
where
    Self: ColAccessCap<F, CIx>,
{
    /// Given variable `x` and position `ix`, it (hybrid) writes `x`
    /// into `ix`, and returns the value.
    fn hcopy(&mut self, x: &Self::Variable, ix: CIx) -> Self::Variable;
}

////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////

/// Write an array of values simultaneously.
pub fn read_column_array<F, Env, const ARR_N: usize, CIx: ColumnIndexer<usize>, ColMap>(
    env: &mut Env,
    column_map: ColMap,
) -> [Env::Variable; ARR_N]
where
    F: PrimeField,
    Env: ColAccessCap<F, CIx>,
    ColMap: Fn(usize) -> CIx,
{
    core::array::from_fn(|i| env.read_column(column_map(i)))
}

/// Write a field element directly as a constant.
pub fn write_column_const<F, Env, CIx: ColumnIndexer<usize>>(env: &mut Env, col: CIx, var: &F)
where
    F: PrimeField,
    Env: ColWriteCap<F, CIx>,
{
    env.write_column(col, &Env::constant(*var));
}

/// Write an array of values simultaneously.
pub fn write_column_array<F, Env, const ARR_N: usize, CIx: ColumnIndexer<usize>, ColMap>(
    env: &mut Env,
    input: [Env::Variable; ARR_N],
    column_map: ColMap,
) where
    F: PrimeField,
    Env: ColWriteCap<F, CIx>,
    ColMap: Fn(usize) -> CIx,
{
    input.iter().enumerate().for_each(|(i, var)| {
        env.write_column(column_map(i), var);
    })
}

/// Write an array of /field/ values simultaneously.
pub fn write_column_array_const<F, Env, const ARR_N: usize, CIx: ColumnIndexer<usize>, ColMap>(
    env: &mut Env,
    input: &[F; ARR_N],
    column_map: ColMap,
) where
    F: PrimeField,
    Env: ColWriteCap<F, CIx>,
    ColMap: Fn(usize) -> CIx,
{
    input.iter().enumerate().for_each(|(i, var)| {
        env.write_column(column_map(i), &Env::constant(*var));
    })
}
