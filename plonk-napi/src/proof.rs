use crate::vector::{fp::NapiVecVecFp, fq::NapiVecVecFq, NapiFlatVector, NapiVector};
use ark_ec::AffineRepr;
use ark_ff::One;
use core::array;
use kimchi::{
    circuits::{
        lookup::runtime_tables::RuntimeTable,
        wires::{COLUMNS, PERMUTS},
    },
    groupmap::GroupMap,
    proof::{
        LookupCommitments, PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof,
        RecursionChallenge,
    },
    prover_index::ProverIndex,
    verifier::{batch_verify, Context},
};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use napi::{
    bindgen_prelude::{sys, ClassInstance, External, FromNapiValue, Result},
    Error as NapiError, Status,
};
use napi_derive::napi;
use paste::paste;
use poly_commitment::commitment::CommitmentCurve; // Import CommitmentCurve trait
use poly_commitment::{ipa::OpeningProof, PolyComm, SRS};

macro_rules! impl_proof {
    (
     $NapiG: ty,
     $G: ty,
     $NapiF: ty,
     $F: ty,
     $NapiPolyComm: ty,
     $NapiSrs: ty,
     $NapiIndex: ty,
     $NapiVerifierIndex: ty,
     $NapiVecVec: ty,
     $field_name: ident,
     $NapiRuntimeTable: ty,
     ) => {
        paste! {
            // type NapiVecVecF = [<NapiVecVec $field_name:camel>];

            #[napi(object, js_name = [<Wasm $field_name:camel PointEvaluations>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel PointEvaluations>] {
                pub zeta: NapiVector<$NapiF>,
                pub zeta_omega: NapiVector<$NapiF>,
            }

            type NapiPointEvaluations = [<Napi $field_name:camel PointEvaluations>];

            impl From<&PointEvaluations<Vec<$F>>> for NapiPointEvaluations {
                fn from(x: &PointEvaluations<Vec<$F>>) -> Self {
                    let zeta: Vec<$NapiF> = x.zeta.iter().cloned().map(Into::into).collect();
                    let zeta_omega: Vec<$NapiF> = x
                        .zeta_omega
                        .iter()
                        .cloned()
                        .map(Into::into)
                        .collect();
                    Self {
                        zeta: zeta.into(),
                        zeta_omega: zeta_omega.into(),
                    }
                }
            }

            #[napi(object, js_name = [<Wasm $field_name:camel ProofEvaluationsObject>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel ProofEvaluationsObject>] {
                pub public: Option<NapiPointEvaluations>,
                pub w: NapiVector<NapiPointEvaluations>,
                pub z: NapiPointEvaluations,
                pub s: NapiVector<NapiPointEvaluations>,
                pub coefficients: NapiVector<NapiPointEvaluations>,
                pub generic_selector: NapiPointEvaluations,
                pub poseidon_selector: NapiPointEvaluations,
                pub complete_add_selector: NapiPointEvaluations,
                pub mul_selector: NapiPointEvaluations,
                pub emul_selector: NapiPointEvaluations,
                pub endomul_scalar_selector: NapiPointEvaluations,
                pub range_check0_selector: Option<NapiPointEvaluations>,
                pub range_check1_selector: Option<NapiPointEvaluations>,
                pub foreign_field_add_selector: Option<NapiPointEvaluations>,
                pub foreign_field_mul_selector: Option<NapiPointEvaluations>,
                pub xor_selector: Option<NapiPointEvaluations>,
                pub rot_selector: Option<NapiPointEvaluations>,
                pub lookup_aggregation: Option<NapiPointEvaluations>,
                pub lookup_table: Option<NapiPointEvaluations>,
                pub lookup_sorted: NapiVector<Option<NapiPointEvaluations>>,
                pub runtime_lookup_table: Option<NapiPointEvaluations>,
                pub runtime_lookup_table_selector: Option<NapiPointEvaluations>,
                pub xor_lookup_selector: Option<NapiPointEvaluations>,
                pub lookup_gate_lookup_selector: Option<NapiPointEvaluations>,
                pub range_check_lookup_selector: Option<NapiPointEvaluations>,
                pub foreign_field_mul_lookup_selector: Option<NapiPointEvaluations>,
            }

            // Use the object representation as the JS-exposed type.
            pub type [<Napi $field_name:camel ProofEvaluations>] = [<Napi $field_name:camel ProofEvaluationsObject>];
            type NapiProofEvaluations = [<Napi $field_name:camel ProofEvaluations>];

            // Field-specific helpers to avoid name clashes between fp/fq instantiations.
            fn [<point_evals_from_napi_ $field_name:snake>](
                evals: NapiPointEvaluations,
            ) -> PointEvaluations<Vec<$F>> {
                PointEvaluations {
                    zeta: evals.zeta.into_iter().map(Into::into).collect(),
                    zeta_omega: evals.zeta_omega.into_iter().map(Into::into).collect(),
                }
            }

            fn [<point_evals_into_napi_ $field_name:snake>](
                evals: &PointEvaluations<Vec<$F>>,
            ) -> NapiPointEvaluations {
                evals.into()
            }

            fn [<proof_evals_from_napi_object_ $field_name:snake>](
                x: NapiProofEvaluations,
            ) -> std::result::Result<ProofEvaluations<PointEvaluations<Vec<$F>>>, NapiError> {
                fn invalid_len(name: &str, expected: usize, got: usize) -> NapiError {
                    NapiError::new(
                        Status::InvalidArg,
                        format!("{name}: expected length {expected}, got {got}"),
                    )
                }

                let w_vec: Vec<_> = x
                    .w
                    .into_iter()
                    .map([<point_evals_from_napi_ $field_name:snake>])
                    .collect();
                let w_len = w_vec.len();
                let w: [PointEvaluations<Vec<$F>>; COLUMNS] = w_vec
                    .try_into()
                    .map_err(|_| invalid_len("evals.w", COLUMNS, w_len))?;

                let s_expected = PERMUTS - 1;
                let s_vec: Vec<_> = x
                    .s
                    .into_iter()
                    .map([<point_evals_from_napi_ $field_name:snake>])
                    .collect();
                let s_len = s_vec.len();
                let s: [PointEvaluations<Vec<$F>>; PERMUTS - 1] = s_vec
                    .try_into()
                    .map_err(|_| invalid_len("evals.s", s_expected, s_len))?;

                let coeffs_vec: Vec<_> = x
                    .coefficients
                    .into_iter()
                    .map([<point_evals_from_napi_ $field_name:snake>])
                    .collect();
                let coeffs_len = coeffs_vec.len();
                let coefficients: [PointEvaluations<Vec<$F>>; COLUMNS] = coeffs_vec
                    .try_into()
                    .map_err(|_| invalid_len("evals.coefficients", COLUMNS, coeffs_len))?;

                let lookup_sorted_vec: Vec<_> = x
                    .lookup_sorted
                    .into_iter()
                    .map(|v| v.map([<point_evals_from_napi_ $field_name:snake>]))
                    .collect();
                let lookup_sorted_len = lookup_sorted_vec.len();
                let lookup_sorted: [Option<PointEvaluations<Vec<$F>>>; 5] = lookup_sorted_vec
                    .try_into()
                    .map_err(|_| invalid_len("evals.lookup_sorted", 5, lookup_sorted_len))?;

                Ok(ProofEvaluations {
                    public: x.public.map([<point_evals_from_napi_ $field_name:snake>]),
                    w,
                    z: [<point_evals_from_napi_ $field_name:snake>](x.z),
                    s,
                    coefficients,
                    generic_selector: [<point_evals_from_napi_ $field_name:snake>](x.generic_selector),
                    poseidon_selector: [<point_evals_from_napi_ $field_name:snake>](x.poseidon_selector),
                    complete_add_selector: [<point_evals_from_napi_ $field_name:snake>](x.complete_add_selector),
                    mul_selector: [<point_evals_from_napi_ $field_name:snake>](x.mul_selector),
                    emul_selector: [<point_evals_from_napi_ $field_name:snake>](x.emul_selector),
                    endomul_scalar_selector: [<point_evals_from_napi_ $field_name:snake>](x.endomul_scalar_selector),
                    range_check0_selector: x.range_check0_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    range_check1_selector: x.range_check1_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    foreign_field_add_selector: x.foreign_field_add_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    foreign_field_mul_selector: x.foreign_field_mul_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    xor_selector: x.xor_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    rot_selector: x.rot_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    lookup_aggregation: x.lookup_aggregation.map([<point_evals_from_napi_ $field_name:snake>]),
                    lookup_table: x.lookup_table.map([<point_evals_from_napi_ $field_name:snake>]),
                    lookup_sorted,
                    runtime_lookup_table: x.runtime_lookup_table.map([<point_evals_from_napi_ $field_name:snake>]),
                    runtime_lookup_table_selector: x.runtime_lookup_table_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    xor_lookup_selector: x.xor_lookup_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    lookup_gate_lookup_selector: x.lookup_gate_lookup_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    range_check_lookup_selector: x.range_check_lookup_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                    foreign_field_mul_lookup_selector: x.foreign_field_mul_lookup_selector.map([<point_evals_from_napi_ $field_name:snake>]),
                })
            }

            impl From<NapiProofEvaluations> for ProofEvaluations<PointEvaluations<Vec<$F>>> {
                fn from(x: NapiProofEvaluations) -> Self {
                    [<proof_evals_from_napi_object_ $field_name:snake>](x)
                        .expect("invalid proof evaluations shape")
                }
            }

            impl From<ProofEvaluations<PointEvaluations<Vec<$F>>>> for NapiProofEvaluations {
                fn from(x: ProofEvaluations<PointEvaluations<Vec<$F>>>) -> Self {
                    [<Napi $field_name:camel ProofEvaluationsObject>] {
                        public: x.public.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        w: x.w.iter().map([<point_evals_into_napi_ $field_name:snake>]).collect(),
                        z: (&x.z).into(),
                        s: x.s.iter().map([<point_evals_into_napi_ $field_name:snake>]).collect(),
                        coefficients: x.coefficients.iter().map([<point_evals_into_napi_ $field_name:snake>]).collect(),
                        generic_selector: (&x.generic_selector).into(),
                        poseidon_selector: (&x.poseidon_selector).into(),
                        complete_add_selector: (&x.complete_add_selector).into(),
                        mul_selector: (&x.mul_selector).into(),
                        emul_selector: (&x.emul_selector).into(),
                        endomul_scalar_selector: (&x.endomul_scalar_selector).into(),
                        range_check0_selector: x.range_check0_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        range_check1_selector: x.range_check1_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        foreign_field_add_selector: x.foreign_field_add_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        foreign_field_mul_selector: x.foreign_field_mul_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        xor_selector: x.xor_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        rot_selector: x.rot_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        lookup_aggregation: x.lookup_aggregation.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        lookup_table: x.lookup_table.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        lookup_sorted: x
                            .lookup_sorted
                            .iter()
                            .map(|v| v.as_ref().map([<point_evals_into_napi_ $field_name:snake>]))
                            .collect(),
                        runtime_lookup_table: x.runtime_lookup_table.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        runtime_lookup_table_selector: x.runtime_lookup_table_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        xor_lookup_selector: x.xor_lookup_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        lookup_gate_lookup_selector: x.lookup_gate_lookup_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        range_check_lookup_selector: x.range_check_lookup_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                        foreign_field_mul_lookup_selector: x.foreign_field_mul_lookup_selector.as_ref().map([<point_evals_into_napi_ $field_name:snake>]),
                    }
                }
            }

            #[napi(js_name = [<Wasm $field_name:camel LookupCommitments>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel LookupCommitments>]
            {
                #[napi(skip)]
                pub sorted: NapiVector<$NapiPolyComm>,
                #[napi(skip)]
                pub aggreg: $NapiPolyComm,
                #[napi(skip)]
                pub runtime: Option<$NapiPolyComm>,
            }

            type NapiLookupCommitments = [<Napi $field_name:camel LookupCommitments>];

            #[napi]
            impl [<Napi $field_name:camel LookupCommitments>] {
                #[napi(constructor)]
                pub fn new(
                    sorted: NapiVector<$NapiPolyComm>,
                    aggreg: $NapiPolyComm,
                    runtime: Option<$NapiPolyComm>) -> Self {
                    NapiLookupCommitments { sorted, aggreg, runtime }
                }

                #[napi(getter)]
                pub fn sorted(&self) -> NapiVector<$NapiPolyComm> {
                    self.sorted.clone()
                }

                #[napi(getter)]
                pub fn aggreg(&self) -> $NapiPolyComm {
                    self.aggreg.clone()
                }

                #[napi(getter)]
                pub fn runtime(&self) -> Option<$NapiPolyComm> {
                    self.runtime.clone()
                }

                #[napi(setter, js_name="set_sorted")]
                pub fn set_sorted(&mut self, s: NapiVector<$NapiPolyComm>) {
                    self.sorted = s
                }

                #[napi(setter, js_name="set_aggreg")]
                pub fn set_aggreg(&mut self, a: $NapiPolyComm) {
                    self.aggreg = a
                }

                #[napi(setter, js_name="set_runtime")]
                pub fn set_runtime(&mut self, r: Option<$NapiPolyComm>) {
                    self.runtime = r
                }
            }

            impl From<LookupCommitments<$G>> for NapiLookupCommitments {
                fn from(x: LookupCommitments<$G>) -> Self {
                    NapiLookupCommitments {
                        sorted: x.sorted.into_iter().map(Into::into).collect(),
                        aggreg: x.aggreg.into(),
                        runtime: x.runtime.map(Into::into)
                    }
                }
            }

            impl From<NapiLookupCommitments> for LookupCommitments<$G> {
                fn from(x: NapiLookupCommitments) -> Self {
                    LookupCommitments {
                        sorted: x.sorted.into_iter().map(Into::into).collect(),
                        aggreg: x.aggreg.into(),
                        runtime: x.runtime.map(Into::into)
                    }
                }
            }

            impl FromNapiValue for [<Napi $field_name:camel LookupCommitments>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel LookupCommitments>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

            #[napi(js_name = [<Wasm $field_name:camel ProverCommitments>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel ProverCommitments>]
            {
                #[napi(skip)]
                pub w_comm: NapiVector<$NapiPolyComm>,
                #[napi(skip)]
                pub z_comm: $NapiPolyComm,
                #[napi(skip)]
                pub t_comm: $NapiPolyComm,
                #[napi(skip)]
                pub lookup: Option<NapiLookupCommitments>,
            }

            type NapiProverCommitments = [<Napi $field_name:camel ProverCommitments>];

            #[napi]
            impl [<Napi $field_name:camel ProverCommitments>] {
                #[napi(constructor)]
                pub fn new(
                    w_comm: NapiVector<$NapiPolyComm>,
                    z_comm: $NapiPolyComm,
                    t_comm: $NapiPolyComm,
                    lookup: Option<NapiLookupCommitments>
                ) -> Self {
                    NapiProverCommitments { w_comm, z_comm, t_comm, lookup }
                }

                #[napi(getter, js_name="w_comm")]
                pub fn w_comm(&self) -> NapiVector<$NapiPolyComm> {
                    self.w_comm.clone()
                }
                #[napi(getter, js_name="z_comm")]
                pub fn z_comm(&self) -> $NapiPolyComm {
                    self.z_comm.clone()
                }
                #[napi(getter, js_name="t_comm")]
                pub fn t_comm(&self) -> $NapiPolyComm {
                    self.t_comm.clone()
                }

                #[napi(getter)]
                pub fn lookup(&self) -> Option<NapiLookupCommitments> {
                    self.lookup.clone()
                }

                #[napi(setter, js_name="set_w_comm")]
                pub fn set_w_comm(&mut self, x: NapiVector<$NapiPolyComm>) {
                    self.w_comm = x
                }
                #[napi(setter, js_name="set_z_comm")]
                pub fn set_z_comm(&mut self, x: $NapiPolyComm) {
                    self.z_comm = x
                }
                #[napi(setter, js_name="set_t_comm")]
                pub fn set_t_comm(&mut self, x: $NapiPolyComm) {
                    self.t_comm = x
                }

                #[napi(setter, js_name="set_lookup")]
                pub fn set_lookup(&mut self, l: Option<NapiLookupCommitments>) {
                    self.lookup = l
                }
            }

            impl From<ProverCommitments<$G>> for NapiProverCommitments {
                fn from(x: ProverCommitments<$G>) -> Self {
                    NapiProverCommitments {
                        w_comm: x.w_comm.iter().map(Into::into).collect(),
                        z_comm: x.z_comm.into(),
                        t_comm: x.t_comm.into(),
                        lookup: x.lookup.map(Into::into),
                    }
                }
            }

            impl From<NapiProverCommitments> for ProverCommitments<$G> {
                fn from(x: NapiProverCommitments) -> Self {
                    ProverCommitments {
                        w_comm: core::array::from_fn(|i| (&x.w_comm[i]).into()),
                        z_comm: x.z_comm.into(),
                        t_comm: x.t_comm.into(),
                        lookup: x.lookup.map(Into::into),
                    }
                }
            }

            impl FromNapiValue for [<Napi $field_name:camel ProverCommitments>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel ProverCommitments>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

            #[napi(js_name = [<Wasm $field_name:camel OpeningProof>] )]
            #[derive(Clone, Debug)]
            pub struct [<Napi $field_name:camel OpeningProof>] {
                #[napi(skip)]
                pub lr_0: NapiVector<$NapiG>, // vector of rounds of L commitments
                #[napi(skip)]
                pub lr_1: NapiVector<$NapiG>, // vector of rounds of R commitments
                #[napi(skip)]
                pub delta: $NapiG,
                pub z1: $NapiF,
                pub z2: $NapiF,
                #[napi(skip)]
                pub sg: $NapiG,
            }

            type NapiOpeningProof = [<Napi $field_name:camel OpeningProof>];

            #[napi]
            impl [<Napi $field_name:camel OpeningProof>] {
                #[napi(constructor)]
                pub fn new(
                    lr_0: NapiVector<$NapiG>,
                    lr_1: NapiVector<$NapiG>,
                    delta: $NapiG,
                    z1: $NapiF,
                    z2: $NapiF,
                    sg: $NapiG) -> Self {
                    NapiOpeningProof { lr_0, lr_1, delta, z1, z2, sg }
                }

                #[napi(getter, js_name="lr_0")]
                pub fn lr_0(&self) -> NapiVector<$NapiG> {
                    self.lr_0.clone()
                }
                #[napi(getter, js_name="lr_1")]
                pub fn lr_1(&self) -> NapiVector<$NapiG> {
                    self.lr_1.clone()
                }
                #[napi(getter)]
                pub fn delta(&self) -> $NapiG {
                    self.delta.clone()
                }
                #[napi(getter)]
                pub fn sg(&self) -> $NapiG {
                    self.sg.clone()
                }

                #[napi(setter, js_name="set_lr_0")]
                pub fn set_lr_0(&mut self, lr_0: NapiVector<$NapiG>) {
                    self.lr_0 = lr_0
                }
                #[napi(setter, js_name="set_lr_1")]
                pub fn set_lr_1(&mut self, lr_1: NapiVector<$NapiG>) {
                    self.lr_1 = lr_1
                }
                #[napi(setter, js_name="set_delta")]
                pub fn set_delta(&mut self, delta: $NapiG) {
                    self.delta = delta
                }
                #[napi(setter, js_name="set_sg")]
                pub fn set_sg(&mut self, sg: $NapiG) {
                    self.sg = sg
                }
            }

            impl From<NapiOpeningProof> for OpeningProof<$G> {
                fn from(x: NapiOpeningProof) -> Self {
                    let NapiOpeningProof {lr_0, lr_1, delta, z1, z2, sg} = x;
                    OpeningProof {
                        lr: lr_0.into_iter().zip(lr_1.into_iter()).map(|(x, y)| (x.into(), y.into())).collect(),
                        delta: delta.into(),
                        z1: z1.into(),
                        z2: z2.into(),
                        sg: sg.into(),
                    }
                }
            }

            impl From<OpeningProof<$G>> for NapiOpeningProof {
                fn from(x: OpeningProof<$G>) -> Self {
                    let (lr_0, lr_1) = x.lr.clone().into_iter().map(|(x, y)| (x.into(), y.into())).unzip();
                    NapiOpeningProof {
                        lr_0,
                        lr_1,
                        delta: x.delta.clone().into(),
                        z1: x.z1.into(),
                        z2: x.z2.into(),
                        sg: x.sg.clone().into(),
                    }
                }
            }

            impl FromNapiValue for [<Napi $field_name:camel ProverProof>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel ProverProof>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

            #[napi(js_name = [<Wasm $field_name:camel ProverProof>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel ProverProof>] {
                #[napi(skip)]
                pub commitments: NapiProverCommitments,
                #[napi(skip)]
                pub proof: NapiOpeningProof,
                // OCaml doesn't have sized arrays, so we have to convert to a tuple..
                #[napi(skip)]
                pub evals: NapiProofEvaluations,
                #[napi(skip)]
                pub ft_eval1: $NapiF,
                #[napi(skip)]
                pub public: NapiFlatVector<$NapiF>,
                #[napi(skip)]
                pub prev_challenges_scalars: $NapiVecVec,
                #[napi(skip)]
                pub prev_challenges_comms: NapiVector<$NapiPolyComm>,
            }

            type NapiProverProof = [<Napi $field_name:camel ProverProof>];

            impl From<&NapiProverProof> for (ProverProof<$G, OpeningProof<$G>>, Vec<$F>) {
                fn from(x: &NapiProverProof) -> Self {
                    let proof = ProverProof {
                        commitments: x.commitments.clone().into(),
                        proof: x.proof.clone().into(),
                        evals: x.evals.clone().into(),
                        prev_challenges: x.prev_challenges_scalars.0
                            .iter().cloned()
                            .zip(x.prev_challenges_comms.clone().into_iter())
                            .map(|(chals, comm)| RecursionChallenge { chals, comm: comm.into() })
                            .collect(),
                        ft_eval1: x.ft_eval1.clone().into()
                    };
                    let public = x.public.clone().into_iter().map(Into::into).collect();
                    (proof, public)
                }
            }

            impl From<NapiProverProof> for (ProverProof<$G, OpeningProof<$G>>, Vec<$F>) {
                fn from(x: NapiProverProof) -> Self {
                    let proof = ProverProof {
                        commitments: x.commitments.into(),
                        proof: x.proof.into(),
                        evals: x.evals.into(),
                        prev_challenges:
                            x.prev_challenges_scalars.0
                                .iter()
                                .zip((x.prev_challenges_comms).clone().into_iter())
                                .map(|(chals, comm)| {
                                    RecursionChallenge {
                                        chals: chals.clone(),
                                        comm: comm.into(),
                                    }
                                })
                                .collect(),
                        ft_eval1: x.ft_eval1.into()
                    };
                    let public = x.public.into_iter().map(Into::into).collect();
                    (proof, public)
                }
            }

            // Map native proof + public input into a NapiProverProof wrapper so it can
            // be returned directly to JS without an External.
            impl From<(&ProverProof<$G, OpeningProof<$G>>, &Vec<$F>)> for NapiProverProof {
                fn from((proof, public): (&ProverProof<$G, OpeningProof<$G>>, &Vec<$F>)) -> Self {
                    let (scalars, comms): (Vec<Vec<$F>>, Vec<$NapiPolyComm>) = proof
                        .prev_challenges
                        .iter()
                        .map(|RecursionChallenge { chals, comm }| (chals.clone(), comm.clone().into()))
                        .unzip();

                    NapiProverProof {
                        commitments: proof.commitments.clone().into(),
                        proof: proof.proof.clone().into(),
                        evals: proof.evals.clone().into(),
                        ft_eval1: proof.ft_eval1.clone().into(),
                        public: public.clone().into_iter().map(Into::into).collect(),
                        prev_challenges_scalars: scalars.into(),
                        prev_challenges_comms: comms.into(), // NapiVector<$NapiPolyComm>
                    }
                }
            }

            impl From<(ProverProof<$G, OpeningProof<$G>>, Vec<$F>)> for NapiProverProof {
                fn from((proof, public): (ProverProof<$G, OpeningProof<$G>>, Vec<$F>)) -> Self {
                    let (scalars, comms): (Vec<Vec<$F>>, Vec<$NapiPolyComm>) = proof
                        .prev_challenges
                        .into_iter()
                        .map(|RecursionChallenge { chals, comm }| (chals, comm.into()))
                        .unzip();

                    NapiProverProof {
                        commitments: proof.commitments.into(),
                        proof: proof.proof.into(),
                        evals: proof.evals.into(),
                        ft_eval1: proof.ft_eval1.into(),
                        public: public.into_iter().map(Into::into).collect(),
                        prev_challenges_scalars: scalars.into(),
                        prev_challenges_comms: comms.into(),
                    }
                }
            }

            impl FromNapiValue for [<Napi $field_name:camel OpeningProof>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel OpeningProof>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

            #[napi]
            impl [<Napi $field_name:camel ProverProof>] {
                #[napi(constructor)]
                pub fn new(
                    commitments: NapiProverCommitments, // maybe remove FromNapiValue trait implementation and wrap it in External instead
                    proof: NapiOpeningProof,
                    evals: NapiProofEvaluations, // maybe remove FromNapiValue trait implementation and wrap it in External instead
                    ft_eval1: $NapiF,
                    public_: NapiFlatVector<$NapiF>,
                    prev_challenges_scalars: $NapiVecVec,
                    prev_challenges_comms: NapiVector<$NapiPolyComm>) -> Self {
                    NapiProverProof {
                        commitments,
                        proof,
                        evals,
                        ft_eval1,
                        public: public_,
                        prev_challenges_scalars,
                        prev_challenges_comms,
                    }
                }

                #[napi(getter)]
                pub fn commitments(&self) -> NapiProverCommitments {
                    self.commitments.clone()
                }
                #[napi(getter)]
                pub fn proof(&self) -> NapiOpeningProof {
                    self.proof.clone()
                }
                #[napi(getter)]
                pub fn evals(&self) -> NapiProofEvaluations {
                    self.evals.clone()
                }
                #[napi(getter, js_name = "ft_eval1")]
                pub fn ft_eval1(&self) -> $NapiF {
                    self.ft_eval1.clone()
                }
                #[napi(getter, js_name="public_")]
                pub fn public_(&self) -> NapiFlatVector<$NapiF> {
                    self.public.clone()
                }
                #[napi(getter, js_name="prev_challenges_scalars")]
                pub fn prev_challenges_scalars(&self) -> $NapiVecVec {
                    self.prev_challenges_scalars.clone()
                }
                #[napi(getter, js_name="prev_challenges_comms")]
                pub fn prev_challenges_comms(&self) -> NapiVector<$NapiPolyComm> {
                    self.prev_challenges_comms.clone()
                }

                #[napi(setter, js_name="set_commitments")]
                pub fn set_commitments(&mut self, commitments: NapiProverCommitments) {
                    self.commitments = commitments
                }
                #[napi(setter, js_name="set_proof")]
                pub fn set_proof(&mut self, proof: NapiOpeningProof) {
                    self.proof = proof
                }
                #[napi(setter, js_name="set_evals")]
                pub fn set_evals(&mut self, evals: NapiProofEvaluations) {
                    self.evals = evals
                }
                #[napi(setter, js_name = "set_ft_eval1")]
                pub fn set_ft_eval1(&mut self, ft_eval1: $NapiF) {
                    self.ft_eval1 = ft_eval1
                }
                #[napi(setter, js_name="set_public_")]
                pub fn set_public_(&mut self, public_: NapiFlatVector<$NapiF>) {
                    self.public = public_
                }
                #[napi(setter, js_name="set_prev_challenges_scalars")]
                pub fn set_prev_challenges_scalars(&mut self, prev_challenges_scalars: $NapiVecVec) {
                    self.prev_challenges_scalars = prev_challenges_scalars;
                }
                #[napi(setter, js_name="set_prev_challenges_comms")]
                pub fn set_prev_challenges_comms(&mut self, prev_challenges_comms: NapiVector<$NapiPolyComm>) {
                    self.prev_challenges_comms = prev_challenges_comms
                }

                #[napi]
                #[allow(deprecated)]
                pub fn serialize(&self) -> String {
                    let (proof, _public_input) = self.into();
                    let serialized = rmp_serde::to_vec(&proof).unwrap();
                    // Deprecated used on purpose: updating this leads to a bug in o1js
                    base64::encode(serialized)
                }
            }

            // Re-use the prover proof wrapper as the returned type (matching wasm binding).
            type NapiProofF = NapiProverProof;

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_create">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_create>](
                index: &External<$NapiIndex>,
                witness: $NapiVecVec,
                runtime_tables: NapiVector<$NapiRuntimeTable>,
                prev_challenges: NapiFlatVector<$NapiF>,
                prev_sgs: NapiVector<$NapiG>,
            ) -> Result<NapiProofF> {
                println!("Entering proof create NAPI function");
                let (maybe_proof, public_input) = {
                    index
                        .0
                        .srs
                        .as_ref()
                        .get_lagrange_basis(index.0.as_ref().cs.domain.d1);
                    let prev: Vec<RecursionChallenge<$G>> = {
                        if prev_challenges.is_empty() {
                            Vec::new()
                        } else {
                            let challenges_per_sg = prev_challenges.len() / prev_sgs.len();
                            let d = prev_sgs
                                .into_iter()
                                .map(Into::<$G>::into)
                                .enumerate()
                                .map(|(i, sg)| {
                                    let chals = prev_challenges
                                        [(i * challenges_per_sg)..(i + 1) * challenges_per_sg]
                                        .iter()
                                        .cloned()
                                        .map(Into::into)
                                        .collect();
                                    let comm = PolyComm::<$G> { chunks: vec![sg] };
                                    RecursionChallenge { chals, comm }
                                })
                                .collect();
                            d
                        }
                    };
                    let rust_runtime_tables: Vec<RuntimeTable<$F>> = runtime_tables.into_iter().map(Into::into).collect();

                    let witness: [Vec<_>; COLUMNS] = witness
                        .0
                        .try_into()
                        .expect("the witness should be a column of 15 vectors");

                    let index: &ProverIndex<$G, OpeningProof<$G>> = &index.0.as_ref();

                    let public_input = witness[0][0..index.cs.public].to_vec();

                    // Release the runtime lock so that other threads can run using it while we generate the proof.
                    let group_map = GroupMap::<_>::setup();
                    let maybe_proof = ProverProof::create_recursive::<
                        DefaultFqSponge<_, PlonkSpongeConstantsKimchi>,
                        DefaultFrSponge<_, PlonkSpongeConstantsKimchi>,
                        _,
                    >(
                        &group_map,
                        witness,
                        &rust_runtime_tables,
                        index,
                        prev,
                        None,
                        &mut rand::rngs::OsRng,
                    );
                    (maybe_proof, public_input)
                };

                match maybe_proof {
                    Ok(proof) => Ok((proof, public_input).into()),
                    Err(err) => Err(NapiError::new(Status::GenericFailure, err.to_string())),
                }
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_verify">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_verify>](
                index: $NapiVerifierIndex,
                proof: NapiProofF,
            ) -> bool {
                    let group_map = <$G as CommitmentCurve>::Map::setup();
                    let verifier_index = &index.into();
                    let proof_with_public: (ProverProof<$G, OpeningProof<$G>>, Vec<$F>) =
                        proof.into();
                    let (proof, public_input) = (&proof_with_public.0, &proof_with_public.1);
                    batch_verify::<
                        $G,
                        DefaultFqSponge<_, PlonkSpongeConstantsKimchi>,
                        DefaultFrSponge<_, PlonkSpongeConstantsKimchi>,
                        OpeningProof<$G>
                    >(
                        &group_map,
                        &[Context { verifier_index, proof, public_input }]
                    ).is_ok()
            }


        #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_batch_verify">])]
        pub fn [<caml_pasta_ $field_name:snake _plonk_proof_batch_verify>](
                indexes: NapiVector<$NapiVerifierIndex>,
                proofs: NapiVector<NapiProofF>,
            ) -> bool {
                let indexes: Vec<_> = indexes.into_iter().map(Into::into).collect();
                let proofs_native: Vec<(ProverProof<$G, OpeningProof<$G>>, Vec<$F>)> =
                    proofs.into_iter().map(Into::into).collect();

                if indexes.len() != proofs_native.len() {
                    return false;
                }

                let contexts: Vec<_> = indexes
                    .iter()
                    .zip(proofs_native.iter())
                    .map(|(index, proof_with_public)| Context {
                        verifier_index: index,
                        proof: &proof_with_public.0,
                        public_input: &proof_with_public.1,
                    })
                    .collect();

                let group_map = GroupMap::<_>::setup();

                batch_verify::<
                    $G,
                    DefaultFqSponge<_, PlonkSpongeConstantsKimchi>,
                    DefaultFrSponge<_, PlonkSpongeConstantsKimchi>,
                    OpeningProof<$G>
                >(&group_map, &contexts)
                .is_ok()
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_dummy">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_dummy>]() -> NapiProofF {
                fn comm() -> PolyComm<$G> {
                    let g = $G::generator();
                    PolyComm {
                        chunks: vec![g, g, g],
                    }
                }

                let prev = RecursionChallenge {
                    chals: vec![$F::one(), $F::one()],
                    comm: comm(),
                };
                let prev_challenges = vec![prev.clone(), prev.clone(), prev.clone()];

                let g = $G::generator();
                let proof = OpeningProof {
                    lr: vec![(g, g), (g, g), (g, g)],
                    z1: $F::one(),
                    z2: $F::one(),
                    delta: g,
                    sg: g,
                };
                let eval = || PointEvaluations {
                    zeta: vec![$F::one()],
                    zeta_omega: vec![$F::one()],
                };
                let evals = ProofEvaluations {
                    w: core::array::from_fn(|_| eval()),
                    coefficients: core::array::from_fn(|_| eval()),
                    z: eval(),
                    s: core::array::from_fn(|_| eval()),
                    generic_selector: eval(),
                    poseidon_selector: eval(),
                    complete_add_selector: eval(),
                    mul_selector: eval(),
                    emul_selector: eval(),
                    endomul_scalar_selector: eval(),
                    range_check0_selector: None,
                    range_check1_selector: None,
                    foreign_field_add_selector: None,
                    foreign_field_mul_selector: None,
                    xor_selector: None,
                    rot_selector: None,
                    lookup_aggregation: None,
                    lookup_table: None,
                    lookup_sorted: array::from_fn(|_| None),
                    runtime_lookup_table: None,
                    runtime_lookup_table_selector: None,
                    xor_lookup_selector: None,
                    lookup_gate_lookup_selector: None,
                    range_check_lookup_selector: None,
                    foreign_field_mul_lookup_selector: None,
                    public: None,
                };

                let dlogproof = ProverProof {
                    commitments: ProverCommitments {
                        w_comm: core::array::from_fn(|_| comm()),
                        z_comm: comm(),
                        t_comm: comm(),
                        lookup: None,
                    },
                    proof,
                    evals,
                    ft_eval1: $F::one(),
                    prev_challenges,
                };

                let public = vec![$F::one(), $F::one()];
                (dlogproof, public).into()
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_deep_copy">])]
            pub fn [<caml_pasta_ $field_name:snake "_plonk_proof_deep_copy">](
                x: NapiProofF
            ) -> NapiProofF {
                x.clone()
            }
        }
    };
}

pub mod fp {
    use super::*;
    use crate::{
        pasta_fp_plonk_index::WasmPastaFpPlonkIndex as NapiPastaFpPlonkIndex,
        plonk_verifier_index::fp::NapiFpPlonkVerifierIndex,
        poly_comm::vesta::NapiFpPolyComm,
        wrappers::{field::NapiPastaFp, group::NapiGVesta, lookups::NapiFpRuntimeTable},
    };
    use mina_curves::pasta::{Fp, Vesta};

    impl_proof!(
        NapiGVesta,
        Vesta,
        NapiPastaFp,
        Fp,
        NapiFpPolyComm,
        NapiSrs,
        NapiPastaFpPlonkIndex,
        NapiFpPlonkVerifierIndex,
        NapiVecVecFp,
        Fp,
        NapiFpRuntimeTable,
    );
}

pub mod fq {
    use super::*;
    use crate::{
        pasta_fq_plonk_index::WasmPastaFqPlonkIndex as NapiPastaFqPlonkIndex,
        plonk_verifier_index::fq::NapiFqPlonkVerifierIndex,
        poly_comm::pallas::NapiFqPolyComm,
        wrappers::{field::NapiPastaFq, group::NapiGPallas, lookups::NapiFqRuntimeTable},
    };
    use mina_curves::pasta::{Fq, Pallas};

    impl_proof!(
        NapiGPallas,
        Pallas,
        NapiPastaFq,
        Fq,
        NapiFqPolyComm,
        NapiSrs,
        NapiPastaFqPlonkIndex,
        NapiFqPlonkVerifierIndex,
        NapiVecVecFq,
        Fq,
        NapiFqRuntimeTable,
    );
}
