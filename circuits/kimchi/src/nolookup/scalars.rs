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
pub struct LookupEvaluations<Field> {
    /// sorted lookup table polynomial
    pub sorted: Vec<Field>,
    /// lookup aggregation polynomial
    pub aggreg: Field,
    // TODO: May be possible to optimize this away?
    /// lookup table polynomial
    pub table: Field,
}

// TODO: this should really be vectors here, perhaps create another type for chuncked evaluations?
#[derive(Clone)]
pub struct ProofEvaluations<Field> {
    /// witness polynomials
    pub w: [Field; COLUMNS],
    /// permutation polynomial
    pub z: Field,
    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    pub s: [Field; PERMUTS - 1],
    /// lookup-related evaluations
    pub lookup: Option<LookupEvaluations<Field>>,
    /// evaluation of the generic selector polynomial
    pub generic_selector: Field,
    /// evaluation of the poseidon selector polynomial
    pub poseidon_selector: Field,
    /// evaluation of the indexer polynomial
    pub indexer: Field,
}

impl<F: FftField> ProofEvaluations<Vec<F>> {
    pub fn combine(&self, pt: F) -> ProofEvaluations<F> {
        ProofEvaluations::<F> {
            s: array_init(|i| DensePolynomial::eval_polynomial(&self.s[i], pt)),
            w: array_init(|i| DensePolynomial::eval_polynomial(&self.w[i], pt)),
            z: DensePolynomial::eval_polynomial(&self.z, pt),
            lookup: self.lookup.as_ref().map(|l| LookupEvaluations {
                table: DensePolynomial::eval_polynomial(&l.table, pt),
                aggreg: DensePolynomial::eval_polynomial(&l.aggreg, pt),
                sorted: l
                    .sorted
                    .iter()
                    .map(|x| DensePolynomial::eval_polynomial(x, pt))
                    .collect(),
            }),
            generic_selector: DensePolynomial::eval_polynomial(&self.generic_selector, pt),
            poseidon_selector: DensePolynomial::eval_polynomial(&self.poseidon_selector, pt),
            indexer: DensePolynomial::eval_polynomial(&self.indexer, pt),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RandomOracles<F: Field> {
    pub joint_combiner: (ScalarChallenge<F>, F),
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
            joint_combiner: (c, F::zero()),
        }
    }
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use oracle::sponge::caml::CamlScalarChallenge;

    //
    // CamlLookupEvaluations<CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlLookupEvaluations<CamlF> {
        pub sorted: Vec<Vec<CamlF>>,
        pub aggreg: Vec<CamlF>,
        pub table: Vec<CamlF>,
    }

    impl<F, CamlF> From<LookupEvaluations<Vec<F>>> for CamlLookupEvaluations<CamlF>
    where
        F: Clone,
        CamlF: From<F>,
    {
        fn from(le: LookupEvaluations<Vec<F>>) -> Self {
            Self {
                sorted: le
                    .sorted
                    .into_iter()
                    .map(|x| x.into_iter().map(Into::into).collect())
                    .collect(),
                aggreg: le.aggreg.into_iter().map(Into::into).collect(),
                table: le.table.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlLookupEvaluations<CamlF>> for LookupEvaluations<Vec<F>>
    where
        F: From<CamlF> + Clone,
    {
        fn from(pe: CamlLookupEvaluations<CamlF>) -> Self {
            Self {
                sorted: pe
                    .sorted
                    .into_iter()
                    .map(|x| x.into_iter().map(Into::into).collect())
                    .collect(),
                aggreg: pe.aggreg.into_iter().map(Into::into).collect(),
                table: pe.table.into_iter().map(Into::into).collect(),
            }
        }
    }

    //
    // CamlProofEvaluations<CamlF>
    //

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
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
        pub generic_selector: Vec<CamlF>,
        pub poseidon_selector: Vec<CamlF>,
        pub indexer: Vec<CamlF>,
    }

    //
    // ProofEvaluations<Vec<F>> <-> CamlProofEvaluations<CamlF>
    //

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
                generic_selector: pe.generic_selector.into_iter().map(Into::into).collect(),
                poseidon_selector: pe.poseidon_selector.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlProofEvaluations<CamlF>> for ProofEvaluations<Vec<F>>
    where
        F: Clone,
        F: From<CamlF>,
    {
        fn from(cpe: CamlProofEvaluations<CamlF>) -> Self {
            let w = [
                cpe.w.0.into_iter().map(Into::into).collect(),
                cpe.w.1.into_iter().map(Into::into).collect(),
                cpe.w.2.into_iter().map(Into::into).collect(),
                cpe.w.3.into_iter().map(Into::into).collect(),
                cpe.w.4.into_iter().map(Into::into).collect(),
                cpe.w.5.into_iter().map(Into::into).collect(),
                cpe.w.6.into_iter().map(Into::into).collect(),
                cpe.w.7.into_iter().map(Into::into).collect(),
                cpe.w.8.into_iter().map(Into::into).collect(),
                cpe.w.9.into_iter().map(Into::into).collect(),
                cpe.w.10.into_iter().map(Into::into).collect(),
                cpe.w.11.into_iter().map(Into::into).collect(),
                cpe.w.12.into_iter().map(Into::into).collect(),
                cpe.w.13.into_iter().map(Into::into).collect(),
                cpe.w.14.into_iter().map(Into::into).collect(),
            ];
            let s = [
                cpe.s.0.into_iter().map(Into::into).collect(),
                cpe.s.1.into_iter().map(Into::into).collect(),
                cpe.s.2.into_iter().map(Into::into).collect(),
                cpe.s.3.into_iter().map(Into::into).collect(),
                cpe.s.4.into_iter().map(Into::into).collect(),
                cpe.s.5.into_iter().map(Into::into).collect(),
            ];

            Self {
                w,
                z: cpe.z.into_iter().map(Into::into).collect(),
                s,
                lookup: None,
                generic_selector: cpe.generic_selector.into_iter().map(Into::into).collect(),
                poseidon_selector: cpe.poseidon_selector.into_iter().map(Into::into).collect(),
            }
        }
    }

    //
    // RandomOracles<F> <-> CamlRandomOracles<CamlF>
    //

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlRandomOracles<CamlF> {
        pub joint_combiner: (CamlScalarChallenge<CamlF>, CamlF),
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
                joint_combiner: (ro.joint_combiner.0.into(), ro.joint_combiner.1.into()),
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
                joint_combiner: (self.joint_combiner.0.into(), self.joint_combiner.1.into()),
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
