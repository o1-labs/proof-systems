/*****************************************************************************************************************

This source file implements Plonk prover polynomials primitive.

*****************************************************************************************************************/

use algebra::FftField;
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
pub use super::wires::COLUMNS;

// PLONK

#[derive(Clone)]
pub struct WitnessEvals<F: FftField>
{
    pub w: [Evaluations<F, D<F>>; COLUMNS], // wire evaluations
    pub z: Evaluations<F, D<F>>,            // permutation evaluations
}

#[derive(Clone)]
pub struct WitnessShifts<F: FftField>
{
    pub this: WitnessEvals<F>,      // this wire evaluations
    pub next: WitnessEvals<F>,      // next wire evaluations
}

#[derive(Clone)]
pub struct WitnessOverDomains<F: FftField>
{
    pub d4: WitnessShifts<F>,       // evaluations over domain d4
    pub d8: WitnessShifts<F>,       // evaluations over domain d8
}

// PLOOKUP

#[derive(Clone)]
pub struct LookupEvals<F: FftField>
{
    pub l: Evaluations<F, D<F>>,    // aggregation
    pub lw: Evaluations<F, D<F>>,   // lookup witness
    pub h1: Evaluations<F, D<F>>,   // lookup multiset
    pub h2: Evaluations<F, D<F>>,   // lookup multiset
}

#[derive(Clone)]
pub struct LookupShifts<F: FftField>
{
    pub this: LookupEvals<F>,       // this wire evaluations
    pub next: LookupEvals<F>,       // next wire evaluations
}

#[derive(Clone)]
pub struct LookupPolys<F: FftField>
{
    pub l: DensePolynomial<F>,      // aggregation
    pub lw: DensePolynomial<F>,     // lookup witness
    pub h1: DensePolynomial<F>,     // lookup multiset
    pub h2: DensePolynomial<F>,     // lookup multiset
}
