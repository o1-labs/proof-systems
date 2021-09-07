/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use crate::nolookup::scalars::{ProofEvaluations as PE, RandomOracles as RO};
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use oracle::utils::PolyUtils;

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    // Plonk evals
    pub pe: PE<Fs>,

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
            pe: PE::<Vec<F>>::combine(&self.pe, pt),
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
    pub w: (Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs, Fs),
    pub z: Fs,
    pub t: Fs,
    pub f: Fs,
    pub s: (Fs, Fs, Fs, Fs, Fs),
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
                let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14] = self.w;
                (
                    w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14,
                )
            },
            z: self.z,
            t: self.t,
            f: self.f,
            s: {
                let [s0, s1, s2, s3, s4] = self.s;
                (s0, s1, s2, s3, s4)
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
                let (w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14) = evals.w;
                [
                    w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14,
                ]
            },
            z: evals.z,
            t: evals.t,
            f: evals.f,
            s: {
                let (s0, s1, s2, s3, s4) = evals.s;
                [s0, s1, s2, s3, s4]
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
    // Plonk oracles
    pub po: RO<F>,

    // Plookup oracles
    pub beta: F,
    pub gamma: F,
}

impl<F: Field> RandomOracles<F> {
    pub fn zero() -> Self {
        Self {
            po: RO::<F>::default(),
            beta: F::zero(),
            gamma: F::zero(),
        }
    }
}
