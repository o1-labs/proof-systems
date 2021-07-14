/*****************************************************************************************************************

This source file implements Plonk prover polynomials primitive.

*****************************************************************************************************************/

pub use super::wires::COLUMNS;
use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};

#[derive(Clone)]
pub struct WitnessEvals<F: FftField> {
    pub w: [Evaluations<F, D<F>>; COLUMNS], // wire evaluations
    pub z: Evaluations<F, D<F>>,            // permutation evaluations
}

#[derive(Clone)]
pub struct WitnessShifts<F: FftField> {
    pub this: WitnessEvals<F>, // this wire evaluations
    pub next: WitnessEvals<F>, // next wire evaluations
}

#[derive(Clone)]
pub struct WitnessOverDomains<F: FftField> {
    pub d4: WitnessShifts<F>, // evaluations over domain d4
    pub d8: WitnessShifts<F>, // evaluations over domain d8
}
