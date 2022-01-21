/*****************************************************************************************************************

This source file implements Plonk prover polynomials primitive.

*****************************************************************************************************************/

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

#[derive(Clone)]
pub struct WitnessShifts<F: FftField> {
    /// this wire evaluations
    pub this: WitnessEvals<F>,
    /// next wire evaluations
    pub next: WitnessEvals<F>,
}

#[derive(Clone)]
pub struct WitnessOverDomains<F: FftField> {
    /// evaluations over domain d4
    pub d4: WitnessShifts<F>,
    /// evaluations over domain d8
    pub d8: WitnessShifts<F>,
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
