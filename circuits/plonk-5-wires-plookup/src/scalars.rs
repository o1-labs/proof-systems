/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

pub use super::wires::COLUMNS;
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use array_init::array_init;
use oracle::{sponge::ScalarChallenge, utils::PolyUtils};

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    // Plonk evals
    pub w: [Fs; COLUMNS],     // wires
    pub z: Fs,                // permutation aggregaion
    pub t: Fs,                // quotient
    pub f: Fs,                // linearization
    pub s: [Fs; COLUMNS - 1], // permutation
    // Plookup evals
    pub l: Fs,  // lookup aggregaion
    pub lw: Fs, // lookup witness
    pub h1: Fs, // lookup multiset
    pub h2: Fs, // lookup multiset
    pub tb: Fs, // lookup table
}

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            s: array_init(|i| DensePolynomial::eval_polynomial(&self.s[i], pt)),
            w: array_init(|i| DensePolynomial::eval_polynomial(&self.w[i], pt)),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
            t: DensePolynomial::eval_polynomial(&self.t, pt),
            f: DensePolynomial::eval_polynomial(&self.f, pt),
            l: DensePolynomial::eval_polynomial(&self.l, pt),
            lw: DensePolynomial::eval_polynomial(&self.lw, pt),
            h1: DensePolynomial::eval_polynomial(&self.h1, pt),
            h2: DensePolynomial::eval_polynomial(&self.h2, pt),
            tb: DensePolynomial::eval_polynomial(&self.tb, pt),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct CamlProofEvaluations<Fs> {
    pub w: (Fs, Fs, Fs, Fs, Fs),
    pub z: Fs,
    pub t: Fs,
    pub f: Fs,
    pub s: (Fs, Fs, Fs, Fs),
    pub l: Fs,
    pub lw: Fs,
    pub h1: Fs,
    pub h2: Fs,
    pub tb: Fs,
}

#[cfg(feature = "ocaml_types")]
unsafe impl<Fs: ocaml::ToValue> ocaml::ToValue for ProofEvaluations<Fs> {
    fn to_value(self) -> ocaml::Value {
        ocaml::ToValue::to_value(CamlProofEvaluations {
            w: {
                let [w0, w1, w2, w3, w4] = self.w;
                (w0, w1, w2, w3, w4)
            },
            z: self.z,
            t: self.t,
            f: self.f,
            s: {
                let [s0, s1, s2, s3] = self.s;
                (s0, s1, s2, s3)
            },
            l: self.l,
            lw: self.lw,
            h1: self.h1,
            h2: self.h2,
            tb: self.tb,
        })
    }
}

#[cfg(feature = "ocaml_types")]
unsafe impl<Fs: ocaml::FromValue> ocaml::FromValue for ProofEvaluations<Fs> {
    fn from_value(v: ocaml::Value) -> Self {
        let evals: CamlProofEvaluations<Fs> = ocaml::FromValue::from_value(v);
        ProofEvaluations {
            w: {
                let (w0, w1, w2, w3, w4) = evals.w;
                [w0, w1, w2, w3, w4]
            },
            z: evals.z,
            t: evals.t,
            f: evals.f,
            s: {
                let (s0, s1, s2, s3) = evals.s;
                [s0, s1, s2, s3]
            },
            l: evals.l,
            lw: evals.lw,
            h1: evals.h1,
            h2: evals.h2,
            tb: evals.tb,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct RandomOracles<F: Field> {
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

impl<F: Field> RandomOracles<F> {
    pub fn zero() -> Self {
        let c = ScalarChallenge(F::zero());
        Self {
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
