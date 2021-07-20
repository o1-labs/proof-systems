/*****************************************************************************************************************

This source file implements Plonk prover polynomials primitive.

*****************************************************************************************************************/

pub use super::wires::COLUMNS;
use algebra::FftField;
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as EvaluationDomain};

// PLONK

/// Evaluations of the wires and permutation
#[derive(Clone)]
pub struct WitnessEvals<Field: FftField> {
    /// wire evaluations
    pub w: [Evaluations<Field, EvaluationDomain<Field>>; COLUMNS],
    /// permutation evaluations
    pub z: Evaluations<Field, EvaluationDomain<Field>>,
}

#[derive(Clone)]
pub struct WitnessShifts<Field: FftField> {
    /// this wire evaluations
    pub this: WitnessEvals<Field>,
    /// next wire evaluations
    pub next: WitnessEvals<Field>,
}

#[derive(Clone)]
pub struct WitnessOverDomains<Field: FftField> {
    /// evaluations over domain d4
    pub d4: WitnessShifts<Field>,
    /// evaluations over domain d8
    pub d8: WitnessShifts<Field>,
}

// PLOOKUP

#[derive(Clone)]
pub struct LookupEvals<Field: FftField> {
    /// aggregation
    pub l: Evaluations<Field, EvaluationDomain<Field>>,
    /// lookup witness
    pub lw: Evaluations<Field, EvaluationDomain<Field>>,
    /// lookup multiset
    pub h1: Evaluations<Field, EvaluationDomain<Field>>,
    /// lookup multiset
    pub h2: Evaluations<Field, EvaluationDomain<Field>>,
}

#[derive(Clone)]
pub struct LookupShifts<Field: FftField> {
    /// this wire evaluations
    pub this: LookupEvals<Field>,
    /// next wire evaluations
    pub next: LookupEvals<Field>,
}

#[derive(Clone)]
pub struct LookupPolys<Field: FftField> {
    /// aggregation
    pub l: DensePolynomial<Field>,
    /// lookup witness
    pub lw: DensePolynomial<Field>,
    /// lookup multiset
    pub h1: DensePolynomial<Field>,
    /// lookup multiset
    pub h2: DensePolynomial<Field>,
}
