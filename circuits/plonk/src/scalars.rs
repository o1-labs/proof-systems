/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use algebra::Field;
pub use super::wires::COLUMNS;

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    pub w: [Fs; COLUMNS],
    pub z: Fs,
    pub t: Fs,
    pub f: Fs,
    pub s: [Fs; COLUMNS-1],
}

pub struct RandomOracles<F: Field>
{
    pub beta: F,
    pub gamma: F,
    pub alpha: F,
    pub zeta: F,
    pub v: F,
    pub u: F,
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        Self
        {
            beta: F::zero(),
            gamma: F::zero(),
            alpha: F::zero(),
            zeta: F::zero(),
            v: F::zero(),
            u: F::zero(),
        }
    }
}
