/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use crate::wires::*;
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use array_init::array_init;
use o1_utils::ExtendedDensePolynomial;
use oracle::sponge::ScalarChallenge;

#[derive(Clone)]
pub struct ProofEvaluations<Field> {
    /// witness polynomials
    pub w: [Field; COLUMNS],
    /// permutation polynomial
    pub z: Field,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    pub s: [Field; PERMUTS - 1],
}

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            s: array_init(|i| DensePolynomial::eval_polynomial(&self.s[i], pt)),
            w: array_init(|i| DensePolynomial::eval_polynomial(&self.w[i], pt)),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
        }
    }
}

#[derive(Clone, Debug)]
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

impl<F: Field> Default for RandomOracles<F> {
    fn default() -> Self {
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

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use ocaml_gen::OcamlGen;
    use oracle::sponge::caml::CamlScalarChallenge;

    //
    // ProofEvaluations<F> <-> CamlProofEvaluations<CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
    pub struct CamlProofEvaluations<CamlF> {
        pub w: (
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
        ),
        pub z: Vec<CamlF>,
        pub s: (
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
            Vec<CamlF>,
        ),
    }

    impl<F, CamlF> From<ProofEvaluations<Vec<F>>> for CamlProofEvaluations<CamlF>
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<Vec<F>>) -> Self {
            let w = (
                pe.w[0].iter().cloned().map(Into::into).collect(),
                pe.w[1].iter().cloned().map(Into::into).collect(),
                pe.w[2].iter().cloned().map(Into::into).collect(),
                pe.w[3].iter().cloned().map(Into::into).collect(),
                pe.w[4].iter().cloned().map(Into::into).collect(),
                pe.w[5].iter().cloned().map(Into::into).collect(),
                pe.w[6].iter().cloned().map(Into::into).collect(),
                pe.w[7].iter().cloned().map(Into::into).collect(),
                pe.w[8].iter().cloned().map(Into::into).collect(),
                pe.w[9].iter().cloned().map(Into::into).collect(),
                pe.w[10].iter().cloned().map(Into::into).collect(),
                pe.w[11].iter().cloned().map(Into::into).collect(),
                pe.w[12].iter().cloned().map(Into::into).collect(),
                pe.w[13].iter().cloned().map(Into::into).collect(),
                pe.w[14].iter().cloned().map(Into::into).collect(),
            );
            let s = (
                pe.s[0].iter().cloned().map(Into::into).collect(),
                pe.s[1].iter().cloned().map(Into::into).collect(),
                pe.s[2].iter().cloned().map(Into::into).collect(),
                pe.s[3].iter().cloned().map(Into::into).collect(),
                pe.s[4].iter().cloned().map(Into::into).collect(),
                pe.s[5].iter().cloned().map(Into::into).collect(),
            );
            Self {
                w,
                z: pe.z.into_iter().map(Into::into).collect(),
                s,
            }
        }
    }

    impl<F, CamlF> Into<ProofEvaluations<Vec<F>>> for CamlProofEvaluations<CamlF>
    where
        CamlF: Into<F>,
    {
        fn into(self) -> ProofEvaluations<Vec<F>> {
            let w = [
                self.w.0.into_iter().map(Into::into).collect(),
                self.w.1.into_iter().map(Into::into).collect(),
                self.w.2.into_iter().map(Into::into).collect(),
                self.w.3.into_iter().map(Into::into).collect(),
                self.w.4.into_iter().map(Into::into).collect(),
                self.w.5.into_iter().map(Into::into).collect(),
                self.w.6.into_iter().map(Into::into).collect(),
                self.w.7.into_iter().map(Into::into).collect(),
                self.w.8.into_iter().map(Into::into).collect(),
                self.w.9.into_iter().map(Into::into).collect(),
                self.w.10.into_iter().map(Into::into).collect(),
                self.w.11.into_iter().map(Into::into).collect(),
                self.w.12.into_iter().map(Into::into).collect(),
                self.w.13.into_iter().map(Into::into).collect(),
                self.w.14.into_iter().map(Into::into).collect(),
            ];
            let s = [
                self.s.0.into_iter().map(Into::into).collect(),
                self.s.1.into_iter().map(Into::into).collect(),
                self.s.2.into_iter().map(Into::into).collect(),
                self.s.3.into_iter().map(Into::into).collect(),
                self.s.4.into_iter().map(Into::into).collect(),
                self.s.5.into_iter().map(Into::into).collect(),
            ];
            ProofEvaluations {
                w,
                z: self.z.into_iter().map(Into::into).collect(),
                s,
            }
        }
    }

    //
    // RandomOracles<F> <-> CamlRandomOracles<CamlF>
    //

    #[derive(ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
    pub struct CamlRandomOracles<CamlF> {
        pub beta: CamlF,
        pub gamma: CamlF,
        pub alpha_chal: CamlScalarChallenge<CamlF>,
        pub alpha: CamlF,
        pub zeta: CamlF,
        pub v: CamlF,
        pub u: CamlF,
        pub zeta_chal: CamlScalarChallenge<CamlF>,
        pub v_chal: CamlScalarChallenge<CamlF>,
        pub u_chal: CamlScalarChallenge<CamlF>,
    }

    impl<F, CamlF> From<RandomOracles<F>> for CamlRandomOracles<CamlF>
    where
        F: Field,
        CamlF: From<F>,
    {
        fn from(ro: RandomOracles<F>) -> Self {
            Self {
                beta: ro.beta.into(),
                gamma: ro.gamma.into(),
                alpha_chal: ro.alpha_chal.into(),
                alpha: ro.alpha.into(),
                zeta: ro.zeta.into(),
                v: ro.v.into(),
                u: ro.u.into(),
                zeta_chal: ro.zeta_chal.into(),
                v_chal: ro.v_chal.into(),
                u_chal: ro.u_chal.into(),
            }
        }
    }

    impl<F, CamlF> Into<RandomOracles<F>> for CamlRandomOracles<CamlF>
    where
        CamlF: Into<F>,
        F: Field,
    {
        fn into(self) -> RandomOracles<F> {
            RandomOracles {
                beta: self.beta.into(),
                gamma: self.gamma.into(),
                alpha_chal: self.alpha_chal.into(),
                alpha: self.alpha.into(),
                zeta: self.zeta.into(),
                v: self.v.into(),
                u: self.u.into(),
                zeta_chal: self.zeta_chal.into(),
                v_chal: self.v_chal.into(),
                u_chal: self.u_chal.into(),
            }
        }
    }
}
