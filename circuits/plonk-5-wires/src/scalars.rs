/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

pub use super::wires::COLUMNS;
use algebra::{FftField, Field};
use oracle::{sponge::ScalarChallenge, utils::PolyUtils};
use ff_fft::DensePolynomial;
use array_init::array_init;

#[derive(Clone)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct ProofEvaluations<Fs> {
    pub w: [Fs; COLUMNS],
    pub z: Fs,
    pub t: Fs,
    pub f: Fs,
    pub s: [Fs; COLUMNS-1],
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
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
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
