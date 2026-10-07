//! This module implements Plonk prover polynomials primitive.

pub use super::wires::COLUMNS;
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};

// PLONK

/// Evaluations of the wires and permutation
#[derive(Clone)]
pub struct WitnessEvals<F: FftField> {
    /// wire evaluations
    pub w: [Evaluations<F, D<F>>; COLUMNS],
    /// permutation evaluations
    pub z: Evaluations<F, D<F>>,
}

/// The witness and the permutation accumulator, evaluated over `d8`.
///
/// Only the values the quotient is built from: constraints referring to the
/// next row are evaluated by shifting the index into these same evaluations,
/// so no separately shifted copy of the witness is kept.
#[derive(Clone)]
pub struct WitnessOverDomains<F: FftField> {
    /// The wires and the permutation accumulator at each row.
    pub this: WitnessEvals<F>,
    /// The permutation accumulator one row on, which the permutation argument
    /// compares against the accumulator in [`Self::this`].
    pub z_next: Evaluations<F, D<F>>,
}

// PLOOKUP

#[derive(Clone)]
pub struct LookupEvals<F: FftField> {
    /// aggregation
    pub l: Evaluations<F, D<F>>,
    /// lookup witness
    pub lw: Evaluations<F, D<F>>,
    /// lookup multiset
    pub h1: Evaluations<F, D<F>>,
    /// lookup multiset
    pub h2: Evaluations<F, D<F>>,
}

#[derive(Clone)]
pub struct LookupShifts<F: FftField> {
    /// this wire evaluations
    pub this: LookupEvals<F>,
    /// next wire evaluations
    pub next: LookupEvals<F>,
}

#[derive(Clone)]
pub struct LookupPolys<F: FftField> {
    /// aggregation
    pub l: DensePolynomial<F>,
    /// lookup witness
    pub lw: DensePolynomial<F>,
    /// lookup multiset
    pub h1: DensePolynomial<F>,
    /// lookup multiset
    pub h2: DensePolynomial<F>,
}
