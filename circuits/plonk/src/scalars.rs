/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

pub use super::wires::COLUMNS;
use algebra::{FftField, Field};
use oracle::{sponge::ScalarChallenge, utils::PolyUtils};
use ff_fft::DensePolynomial;
use array_init::array_init;

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    pub w: [Fs; COLUMNS],   // wires
    pub z: Fs,              // permutation aggregaion
    pub t: Fs,              // quotient
    pub f: Fs,              // linearization
    pub s: [Fs; COLUMNS-1], // permutation
    pub l: Fs,              // lookup aggregaion
    pub h1: Fs,             // lookup multiset
    pub h2: Fs,             // lookup multiset
    pub tb: Fs,             // lookup table
}

impl<F : FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt : F) -> ProofEvaluations<F> {
        ProofEvaluations::<F>
        {
            s: array_init(|i| DensePolynomial::eval_polynomial(&self.s[i], pt)),
            w: array_init(|i| DensePolynomial::eval_polynomial(&self.w[i], pt)),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
            t: DensePolynomial::eval_polynomial(&self.t, pt),
            f: DensePolynomial::eval_polynomial(&self.f, pt),
            l: DensePolynomial::eval_polynomial(&self.l, pt),
            h1: DensePolynomial::eval_polynomial(&self.h1, pt),
            h2: DensePolynomial::eval_polynomial(&self.h2, pt),
            tb: DensePolynomial::eval_polynomial(&self.tb, pt),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RandomOracles<F: Field>
{
    pub beta1: F,
    pub gamma1: F,
    pub beta2: F,
    pub gamma2: F,
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
            beta1: F::zero(),
            gamma1: F::zero(),
            beta2: F::zero(),
            gamma2: F::zero(),
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
