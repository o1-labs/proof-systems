//! This module implements a witness type.
//! The normal way to instantiate this type is to first create an [Index],
//! and to call [Index::new_witness].

use crate::index::Index;
use ark_ec::AffineCurve;
use ark_ff::Field;
use array_init::array_init;
use commitment_dlog::commitment::CommitmentCurve;
use serde::Serialize;
use serde_with::serde_as;
use std::ops::Range;

/// Number of registers
pub const COLUMNS: usize = 15;

/// Number of registers that can be wired (participating in the permutation)
pub const PERMUTS: usize = 7;

/// The type that represents the execution trace.
/// It represents a table of [REGISTERS] columns, with `n` rows.
/// `n` being the maximum size of the circuit, and the size of the domain.
#[serde_as]
#[derive(Debug, Serialize)]
pub struct Witness<F>
where
    F: Field,
{
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; COLUMNS]")]
    inner: [Vec<F>; COLUMNS],
}

impl<F> Witness<F>
where
    F: Field,
{
    /// Creates a new witness with `rows` rows.
    // TODO: deprecate this
    pub fn new(rows: usize) -> Self {
        Witness {
            inner: array_init(|_| vec![F::zero(); rows]),
        }
    }
    /// Sets the witness to `value` at row `row` and column `col`.
    pub fn set(&mut self, row: usize, col: usize, value: F) {
        self.inner[col][row] = value;
    }

    /// Returns a mutable reference to the columns `cols` requested.
    pub fn get_cols_mut(&mut self, cols: Range<usize>) -> &mut [Vec<F>] {
        &mut self.inner[cols]
    }

    /// Returns the inner witness.
    // TODO: deprecate this
    pub fn inner(self) -> [Vec<F>; COLUMNS] {
        self.inner
    }
}

/// Type alias for the scalar field of a curve
type Fr<G> = <G as AffineCurve>::ScalarField;

impl<G> Index<G>
where
    G: CommitmentCurve,
{
    /// Returns a new witness with `n` rows,
    /// `n` being the size of the domain.
    pub fn new_witness(&self) -> Witness<Fr<G>> {
        Witness::new(self.cs.domain.d1.size as usize)
    }
}

// TODO: deprecate this
impl<F> From<[Vec<F>; COLUMNS]> for Witness<F>
where
    F: Field,
{
    fn from(inner: [Vec<F>; COLUMNS]) -> Self {
        Witness { inner }
    }
}
