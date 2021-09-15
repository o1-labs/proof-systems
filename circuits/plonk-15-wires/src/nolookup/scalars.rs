/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use crate::wires::*;
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use array_init::array_init;
use oracle::{sponge::ScalarChallenge, utils::PolyUtils};

#[derive(Clone)]
pub struct LookupEvaluations<Field> {
    /// sorted lookup table polynomial
    pub sorted: Vec<Field>,
    /// lookup aggregation polynomial
    pub aggreg: Field,
    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    pub table: Field,
}

#[derive(Clone)]
pub struct ProofEvaluations<Field> {
    /// witness polynomials
    pub w: [Field; COLUMNS],
    /// permutation polynomial
    pub z: Field,
    /// quotient polynomial
    pub t: Field,
    /// full polynomial
    pub f: Field,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    pub s: [Field; PERMUTS - 1],
    /// lookup-related evalutions
    pub lookup: Option<LookupEvaluations<Field>>,
}

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            s: array_init(|i| DensePolynomial::eval_polynomial(&self.s[i], pt)),
            w: array_init(|i| DensePolynomial::eval_polynomial(&self.w[i], pt)),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
            t: DensePolynomial::eval_polynomial(&self.t, pt),
            f: DensePolynomial::eval_polynomial(&self.f, pt),
            lookup:
                self.lookup.as_ref().map(|l| {
                    LookupEvaluations {
                        table: DensePolynomial::eval_polynomial(&l.table, pt),
                        aggreg: DensePolynomial::eval_polynomial(&l.aggreg, pt),
                        sorted: l.sorted.iter().map(|x| DensePolynomial::eval_polynomial(x, pt)).collect(),
                    }
                })
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
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct RandomOracles<F: Field> {
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

impl<F: Field> RandomOracles<F> {
    pub fn zero() -> Self {
        let c = ScalarChallenge(F::zero());
        Self {
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
