//! This module implements Plonk prover polynomial evaluations primitive.

use ark_ff::Field;
use mina_poseidon::sponge::ScalarChallenge;

#[derive(Clone, Debug)]
pub struct RandomOracles<F: Field> {
    pub joint_combiner: Option<(ScalarChallenge<F>, F)>,
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
            alpha_chal: c.clone(),
            zeta_chal: c.clone(),
            v_chal: c.clone(),
            u_chal: c,
            joint_combiner: None,
        }
    }
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use mina_poseidon::sponge::caml::CamlScalarChallenge;

    //
    // RandomOracles<F> <-> CamlRandomOracles<CamlF>
    //

    #[derive(ocaml::ToValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlRandomOracles<CamlF> {
        pub joint_combiner: Option<(CamlScalarChallenge<CamlF>, CamlF)>,
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
                joint_combiner: ro.joint_combiner.map(|(l, r)| (l.into(), r.into())),
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

    impl<F, CamlF> From<CamlRandomOracles<CamlF>> for RandomOracles<F>
    where
        CamlF: Into<F>,
        F: Field,
    {
        fn from(caml_ro: CamlRandomOracles<CamlF>) -> Self {
            RandomOracles {
                joint_combiner: caml_ro.joint_combiner.map(|(l, r)| (l.into(), r.into())),
                beta: caml_ro.beta.into(),
                gamma: caml_ro.gamma.into(),
                alpha_chal: caml_ro.alpha_chal.into(),
                alpha: caml_ro.alpha.into(),
                zeta: caml_ro.zeta.into(),
                v: caml_ro.v.into(),
                u: caml_ro.u.into(),
                zeta_chal: caml_ro.zeta_chal.into(),
                v_chal: caml_ro.v_chal.into(),
                u_chal: caml_ro.u_chal.into(),
            }
        }
    }
}
