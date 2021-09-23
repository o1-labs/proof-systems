/*****************************************************************************************************************

This source file implements Plonk prover polynomial evaluations primitive.

*****************************************************************************************************************/

use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use o1_utils::ExtendedDensePolynomial as _;
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

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            l: DensePolynomial::eval_polynomial(&self.l, pt),
            r: DensePolynomial::eval_polynomial(&self.r, pt),
            o: DensePolynomial::eval_polynomial(&self.o, pt),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
            t: DensePolynomial::eval_polynomial(&self.t, pt),
            f: DensePolynomial::eval_polynomial(&self.f, pt),
            sigma1: DensePolynomial::eval_polynomial(&self.sigma1, pt),
            sigma2: DensePolynomial::eval_polynomial(&self.sigma2, pt),
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
    pub struct CamlProofEvaluations<F> {
        pub l: Vec<F>,
        pub r: Vec<F>,
        pub o: Vec<F>,
        pub z: Vec<F>,
        pub t: Vec<F>,
        pub f: Vec<F>,
        pub sigma1: Vec<F>,
        pub sigma2: Vec<F>,
    }

    impl<F, CamlF> From<ProofEvaluations<Vec<F>>> for CamlProofEvaluations<CamlF>
    where
        CamlF: From<F>,
    {
        fn from(pe: ProofEvaluations<Vec<F>>) -> Self {
            Self {
                l: pe.l.into_iter().map(Into::into).collect(),
                r: pe.r.into_iter().map(Into::into).collect(),
                o: pe.o.into_iter().map(Into::into).collect(),
                z: pe.z.into_iter().map(Into::into).collect(),
                t: pe.t.into_iter().map(Into::into).collect(),
                f: pe.f.into_iter().map(Into::into).collect(),
                sigma1: pe.sigma1.into_iter().map(Into::into).collect(),
                sigma2: pe.sigma2.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> Into<ProofEvaluations<Vec<F>>> for CamlProofEvaluations<CamlF>
    where
        CamlF: Into<F>,
    {
        fn into(self) -> ProofEvaluations<Vec<F>> {
            ProofEvaluations {
                l: self.l.into_iter().map(Into::into).collect(),
                r: self.r.into_iter().map(Into::into).collect(),
                o: self.o.into_iter().map(Into::into).collect(),
                z: self.z.into_iter().map(Into::into).collect(),
                t: self.t.into_iter().map(Into::into).collect(),
                f: self.f.into_iter().map(Into::into).collect(),
                sigma1: self.sigma1.into_iter().map(Into::into).collect(),
                sigma2: self.sigma2.into_iter().map(Into::into).collect(),
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
