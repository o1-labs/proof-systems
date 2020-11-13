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

#[derive(Clone, Debug)]
pub struct RandomOracles<F: Field>
{
    pub beta: F,
    pub gamma: F,
    pub alpha_chal: ScalarChallenge<F>,
    pub alpha: F,
    pub zeta: F,
    pub v: F,
    pub u: F,
    pub zeta_chal: ScalarChallenge<F>,
    pub v_chal: ScalarChallenge<F>,
    pub u_chal: ScalarChallenge<F>,
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        let c = ScalarChallenge(F::zero());
        Self
        {
            beta: F::zero(),
            gamma: F::zero(),
            alpha: F::zero(),
            zeta: F::zero(),
            v: F::zero(),
            u: F::zero(),
            alpha_chal: c,
            zeta_chal: c,
            v_chal: c,
            u_chal: c,
        }
    }
}
