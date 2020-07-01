/*****************************************************************************************************************

This source file implements Plonk prover plonomials primitive.

*****************************************************************************************************************/

use algebra::FftField;
use ff_fft::{Evaluations, Radix2EvaluationDomain as D};

#[derive(Clone)]
pub struct WitnessEvals<F: FftField>
{
    pub l: Evaluations<F, D<F>>,   // left wire evaluations
    pub r: Evaluations<F, D<F>>,   // right wire evaluations
    pub o: Evaluations<F, D<F>>,   // output wire evaluations
    pub z: Evaluations<F, D<F>>,   // permutation evaluations
}

#[derive(Clone)]
pub struct WitnessShifts<F: FftField>
{
    pub this: WitnessEvals<F>,          // this wire evaluations
    pub next: WitnessEvals<F>,          // next wire evaluations
}

#[derive(Clone)]
pub struct WitnessOverDomains<F: FftField>
{
    pub d2: WitnessShifts<F>,           // evaluations ovrt domain d2
    pub d4: WitnessShifts<F>,           // evaluations ovrt domain d4
}
