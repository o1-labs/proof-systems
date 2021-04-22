/*****************************************************************************************************************

This source file implements Plonk prover polynomials primitive.

*****************************************************************************************************************/

use algebra::FftField;
use ff_fft::{Evaluations, Radix2EvaluationDomain as D};
pub use super::wires::COLUMNS;

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
