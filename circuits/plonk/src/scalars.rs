/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use algebra::Field;
use oracle::sponge::ScalarChallenge;

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    pub l: Fs,
    pub r: Fs,
    pub o: Fs,
    pub z: Fs,
    pub t: Fs,
    pub f: Fs,
    pub sigma1: Fs,
    pub sigma2: Fs,
}

pub struct RandomOracles<F: Field>
{
    pub beta: F,
    pub gamma: F,
    pub alpha: F,
    pub zeta: ScalarChallenge<F>,
    pub v: ScalarChallenge<F>,
    pub u: ScalarChallenge<F>,
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
            zeta: ScalarChallenge(F::zero()),
            v: ScalarChallenge(F::zero()),
            u: ScalarChallenge(F::zero()),
        }
    }
}
