use crate::{
    vector::{NapiFlatVector, NapiVector},
    wrappers::field::{NapiPastaFp, NapiPastaFq},
};
use ark_ff::{One, Zero};
use kimchi::{
    circuits::scalars::RandomOracles, proof::ProverProof,
    verifier_index::VerifierIndex as DlogVerifierIndex,
};
use mina_poseidon::{
    self,
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use napi::{bindgen_prelude::*, Error as NapiError, Status};
use napi_derive::napi;
use paste::paste;
use poly_commitment::{
    commitment::{shift_scalar, PolyComm},
    ipa::OpeningProof,
    SRS,
};

macro_rules! impl_oracles {
    ($NapiF: ty,
     $F: ty,
     $NapiG: ty,
     $G: ty,
     $NapiPolyComm: ty,
     $NapiProverProof: ty,
     $index: ty,
     $curve_params: ty,
     $field_name: ident) => {

        paste! {
            use mina_poseidon::sponge::ScalarChallenge;

            #[napi(js_name = [<Wasm $field_name:camel RandomOracles>])]
            #[derive(Clone, Copy)]
            pub struct [<Napi $field_name:camel RandomOracles>] {
                #[napi(js_name = "joint_combiner_chal")]
                pub joint_combiner_chal: Option<$NapiF>,
                #[napi(js_name = "joint_combiner")]
                pub joint_combiner: Option<$NapiF>,
                pub beta: $NapiF,
                pub gamma: $NapiF,
                #[napi(js_name = "alpha_chal")]
                pub alpha_chal: $NapiF,
                pub alpha: $NapiF,
                pub zeta: $NapiF,
                pub v: $NapiF,
                pub u: $NapiF,
                #[napi(js_name = "zeta_chal")]
                pub zeta_chal: $NapiF,
                #[napi(js_name = "v_chal")]
                pub v_chal: $NapiF,
                #[napi(js_name = "u_chal")]
                pub u_chal: $NapiF,
            }
            type NapiRandomOracles = [<Napi $field_name:camel RandomOracles>];

            #[napi]
            impl [<Napi $field_name:camel RandomOracles>] {
                #[napi(constructor)]
                #[allow(clippy::too_many_arguments)]
                pub fn new(
                    joint_combiner_chal: Option<$NapiF>,
                    joint_combiner: Option<$NapiF>,
                    beta: $NapiF,
                    gamma: $NapiF,
                    alpha_chal: $NapiF,
                    alpha: $NapiF,
                    zeta: $NapiF,
                    v: $NapiF,
                    u: $NapiF,
                    zeta_chal: $NapiF,
                    v_chal: $NapiF,
                    u_chal: $NapiF) -> Self  {
                    Self {
                        joint_combiner_chal,
                        joint_combiner,
                        beta,
                        gamma,
                        alpha_chal,
                        alpha,
                        zeta,
                        v,
                        u,
                        zeta_chal,
                        v_chal,
                        u_chal,
                    }
                }
            }

            impl From<RandomOracles<$F>> for NapiRandomOracles
            {
                fn from(ro: RandomOracles<$F>) -> Self {
                    Self {
                        joint_combiner_chal: ro.joint_combiner.as_ref().map(|x| x.0.0.into()),
                        joint_combiner: ro.joint_combiner.as_ref().map(|x| x.1.into()),
                        beta: ro.beta.into(),
                        gamma: ro.gamma.into(),
                        alpha_chal: ro.alpha_chal.0.into(),
                        alpha: ro.alpha.into(),
                        zeta: ro.zeta.into(),
                        v: ro.v.into(),
                        u: ro.u.into(),
                        zeta_chal: ro.zeta_chal.0.into(),
                        v_chal: ro.v_chal.0.into(),
                        u_chal: ro.u_chal.0.into(),
                    }
                }
            }

            impl From<NapiRandomOracles> for RandomOracles<$F>
            {
                fn from(ro: NapiRandomOracles) -> Self {
                    Self {
                        joint_combiner: ro.joint_combiner_chal.and_then(|x| {
                            ro.joint_combiner.map(|y| (ScalarChallenge(x.into()), y.into()))
                        }),
                        beta: ro.beta.into(),
                        gamma: ro.gamma.into(),
                        alpha_chal: ScalarChallenge(ro.alpha_chal.into()),
                        alpha: ro.alpha.into(),
                        zeta: ro.zeta.into(),
                        v: ro.v.into(),
                        u: ro.u.into(),
                        zeta_chal: ScalarChallenge(ro.zeta_chal.into()),
                        v_chal: ScalarChallenge(ro.v_chal.into()),
                        u_chal: ScalarChallenge(ro.u_chal.into()),
                    }
                }
            }

            impl FromNapiValue for [<Napi $field_name:camel RandomOracles>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel RandomOracles>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

            impl<'a> ToNapiValue for &'a mut [<Napi $field_name:camel RandomOracles>] {
                unsafe fn to_napi_value(
                    env: sys::napi_env,
                    val: Self,
                ) -> Result<sys::napi_value> {
                    <[<Napi $field_name:camel RandomOracles>] as ToNapiValue>::to_napi_value(env, val.clone())
                }
            }

            #[napi(js_name = [<Wasm $field_name:camel Oracles>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel Oracles>] {
                pub o: [<Napi $field_name:camel RandomOracles>],
                #[napi(js_name = "p_eval0")]
                pub p_eval0: $NapiF,
                #[napi(js_name = "p_eval1")]
                pub p_eval1: $NapiF,
                #[napi(skip)]
                pub opening_prechallenges: NapiFlatVector<$NapiF>,
                #[napi(js_name = "digest_before_evaluations")]
                pub digest_before_evaluations: $NapiF,
            }

            #[napi]
            impl [<Napi $field_name:camel Oracles>] {
                #[napi(constructor)]
                pub fn new(
                    o: NapiRandomOracles,
                    p_eval0: $NapiF,
                    p_eval1: $NapiF,
                    opening_prechallenges: NapiFlatVector<$NapiF>,
                    digest_before_evaluations: $NapiF) -> Self {
                    Self {o, p_eval0, p_eval1, opening_prechallenges, digest_before_evaluations}
                }

                #[napi(getter, js_name="opening_prechallenges")]
                pub fn opening_prechallenges(&self) -> NapiFlatVector<$NapiF> {
                    self.opening_prechallenges.clone()
                }

                #[napi(setter, js_name="set_opening_prechallenges")]
                pub fn set_opening_prechallenges(&mut self, x: NapiFlatVector<$NapiF>) {
                    self.opening_prechallenges = x;
                }
            }

            #[napi(js_name = [<$F:snake _oracles_create>])]
            pub fn [<$F:snake _oracles_create>](
                lgr_comm: NapiVector<$NapiPolyComm>, // the bases to commit polynomials
                index: $index,    // parameters
                proof: $NapiProverProof, // the final proof (contains public elements at the beginning)
            ) -> Result<[<Napi $field_name:camel Oracles>]> {
                // conversions
                let result: Result<(RandomOracles<$F>, [Vec<$F>; 2], NapiFlatVector<$NapiF>, $F), String> = {
                    let index: DlogVerifierIndex<$G, OpeningProof<$G>> = index.into();

                    let lgr_comm: Vec<PolyComm<$G>> = lgr_comm
                        .into_iter()
                        .take(proof.public.len())
                        .map(Into::into)
                        .collect();
                    let lgr_comm_refs: Vec<_> = lgr_comm.iter().collect();

                    let p_comm = PolyComm::<$G>::multi_scalar_mul(
                        &lgr_comm_refs,
                        &proof
                            .public
                            .iter()
                            .map(|a| a.clone().into())
                            .map(|s: $F| -s)
                            .collect::<Vec<_>>(),
                    );
                    let p_comm = {
                        index
                            .srs()
                            .mask_custom(
                                p_comm.clone(),
                                &p_comm.map(|_| $F::one()),
                            )
                            .unwrap()
                            .commitment
                    };

                    let (proof, public_input): (ProverProof<$G, OpeningProof<$G>>, Vec<$F>) = proof.into();

                    let oracles_result =
                        proof.oracles::<
                            DefaultFqSponge<$curve_params, PlonkSpongeConstantsKimchi>,
                            DefaultFrSponge<$F, PlonkSpongeConstantsKimchi>
                        >(&index, &p_comm, Some(&public_input));
                    let oracles_result = match oracles_result {
                        Err(e) => {
                            return Err(NapiError::new(Status::GenericFailure, format!("oracles_create: {}", e)));
                        }
                        Ok(cs) => cs,
                    };

                    let (mut sponge, combined_inner_product, p_eval, digest, oracles) = (
                        oracles_result.fq_sponge,
                        oracles_result.combined_inner_product,
                        oracles_result.public_evals,
                        oracles_result.digest,
                        oracles_result.oracles,
                    );

                    sponge.absorb_fr(&[shift_scalar::<$G>(combined_inner_product)]);

                    let opening_prechallenges = proof
                        .proof
                        .prechallenges(&mut sponge)
                        .into_iter()
                        .map(|x| x.0.into())
                        .collect();

                    Ok((oracles, p_eval, opening_prechallenges, digest))
                };

                match result {
                    Ok((oracles, p_eval, opening_prechallenges, digest)) => Ok([<Napi $field_name:camel Oracles>] {
                        o: oracles.into(),
                        p_eval0: p_eval[0][0].into(),
                        p_eval1: p_eval[1][0].into(),
                        opening_prechallenges,
                        digest_before_evaluations: digest.into()
                    }),
                    Err(err) => Err(NapiError::new(Status::GenericFailure, err)),
                }
            }

            #[napi(js_name = [<$F:snake _oracles_dummy>])]
            pub fn [<$F:snake _oracles_dummy>]() -> [<Napi $field_name:camel Oracles>] {
                [<Napi $field_name:camel Oracles>] {
                    o: RandomOracles::<$F>::default().into(),
                    p_eval0: $F::zero().into(),
                    p_eval1: $F::zero().into(),
                    opening_prechallenges: vec![].into(),
                    digest_before_evaluations: $F::zero().into(),
                }
            }

            #[napi(js_name = [<$F:snake _oracles_deep_copy>])]
            pub fn [<$F:snake _oracles_deep_copy>](
                x: $NapiProverProof,
            ) -> $NapiProverProof {
                x
            }
        }
    }
}

pub mod fp {
    use super::*;
    use crate::{
        plonk_verifier_index::fp::NapiFpPlonkVerifierIndex as WasmPlonkVerifierIndex,
        poly_comm::vesta::NapiFpPolyComm as WasmPolyComm,
        proof::fp::NapiFpProverProof as WasmProverProof,
    };
    use mina_curves::pasta::{Fp, Vesta as GAffine, VestaParameters};

    impl_oracles!(
        NapiPastaFp,
        Fp,
        WasmGVesta,
        GAffine,
        WasmPolyComm,
        WasmProverProof,
        WasmPlonkVerifierIndex,
        VestaParameters,
        Fp
    );
}

pub mod fq {
    use super::*;
    use crate::{
        plonk_verifier_index::fq::NapiFqPlonkVerifierIndex as WasmPlonkVerifierIndex,
        poly_comm::pallas::NapiFqPolyComm as WasmPolyComm,
        proof::fq::NapiFqProverProof as WasmProverProof,
    };
    use mina_curves::pasta::{Fq, Pallas as GAffine, PallasParameters};

    impl_oracles!(
        NapiPastaFq,
        Fq,
        WasmGPallas,
        GAffine,
        WasmPolyComm,
        WasmProverProof,
        WasmPlonkVerifierIndex,
        PallasParameters,
        Fq
    );
}
