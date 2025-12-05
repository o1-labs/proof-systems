use crate::{
    tables::{JsRuntimeTableFp, JsRuntimeTableFq},
    vector::{
        fp::WasmVecVecFp as NapiVecVecFp, fq::WasmVecVecFq as NapiVecVecFq, NapiFlatVector,
        NapiVector,
    },
};
use ark_ec::AffineRepr;
use ark_ff::One;
use core::array;
use kimchi::{
    circuits::{lookup::runtime_tables::RuntimeTable, wires::COLUMNS},
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
     $field_name: ident
     ) => {
        paste! {
            // type NapiVecVecF = [<NapiVecVec $field_name:camel>];

            #[napi(js_name = [<Wasm $field_name:camel ProofEvaluations>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel ProofEvaluations>](
                ProofEvaluations<PointEvaluations<Vec<$F>>>
            );

            type NapiProofEvaluations = [<Napi $field_name:camel ProofEvaluations>];

            impl From<NapiProofEvaluations> for ProofEvaluations<PointEvaluations<Vec<$F>>> {
                fn from(x: NapiProofEvaluations) -> Self {
                    x.0
                }
            }

            impl From<ProofEvaluations<PointEvaluations<Vec<$F>>>> for NapiProofEvaluations {
                fn from(x: ProofEvaluations<PointEvaluations<Vec<$F>>>) -> Self {
                    Self(x)
                }
            }

            impl FromNapiValue for [<Napi $field_name:camel ProofEvaluations>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel ProofEvaluations>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
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
                pub ft_eval1: $NapiF,
                #[napi(skip)]
                pub public: NapiFlatVector<$NapiF>,
                #[napi(skip)]
                pub prev_challenges_scalars: Vec<Vec<$F>>,
                #[napi(skip)]
                pub prev_challenges_comms:NapiVector<$NapiPolyComm>,
            }

            type NapiProverProof = [<Napi $field_name:camel ProverProof>];

            impl From<&NapiProverProof> for (ProverProof<$G, OpeningProof<$G>>, Vec<$F>) {
                fn from(x: &NapiProverProof) -> Self {
                    let proof = ProverProof {
                        commitments: x.commitments.clone().into(),
                        proof: x.proof.clone().into(),
                        evals: x.evals.clone().into(),
                        prev_challenges:
                            (&x.prev_challenges_scalars)
                                .into_iter()
                                .zip((&x.prev_challenges_comms).into_iter())
                                .map(|(chals, comm)| {
                                    RecursionChallenge {
                                        chals: chals.clone(),
                                        comm: comm.into(),
                                    }
                                })
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
                            (x.prev_challenges_scalars)
                                .into_iter()
                                .zip((x.prev_challenges_comms).into_iter())
                                .map(|(chals, comm)| {
                                    RecursionChallenge {
                                        chals: chals.into(),
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
                        prev_challenges_scalars: prev_challenges_scalars.0,
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
                #[napi(getter, js_name="public_")]
                pub fn public_(&self) -> NapiFlatVector<$NapiF> {
                    self.public.clone()
                }
                #[napi(getter, js_name="prev_challenges_scalars")]
                pub fn prev_challenges_scalars(&self) -> $NapiVecVec {
                    [<NapiVecVec $field_name:camel>](self.prev_challenges_scalars.clone())
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
                #[napi(setter, js_name="set_public_")]
                pub fn set_public_(&mut self, public_: NapiFlatVector<$NapiF>) {
                    self.public = public_
                }
                #[napi(setter, js_name="set_prev_challenges_scalars")]
                pub fn set_prev_challenges_scalars(&mut self, prev_challenges_scalars: $NapiVecVec) {
                    self.prev_challenges_scalars = prev_challenges_scalars.0
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

            #[derive(Clone)]
            pub struct [<NapiProof $field_name:camel>] {
                pub proof: ProverProof<$G, OpeningProof<$G>>,
                pub public_input: Vec<$F>,
            }

            type NapiProofF = [<NapiProof $field_name:camel>];
            type JsRuntimeTableF = [<JsRuntimeTable $field_name:camel>];

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_create">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_create>](
                index: &External<$NapiIndex>,
                witness: $NapiVecVec,
                runtime_tables: NapiVector<JsRuntimeTableF>,
                prev_challenges: NapiFlatVector<$NapiF>,
                prev_sgs: NapiVector<$NapiG>,
            ) -> Result<External<NapiProofF>> {
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

                    let rust_runtime_tables: Vec<RuntimeTable<$F>> = runtime_tables
                        .into_iter()
                        .flat_map(|table| {
                            let JsRuntimeTableF { id, data } = table;
                            data.into_iter().map(move |column| {
                                let values = NapiFlatVector::<$NapiF>::from_bytes(column.to_vec())
                                    .into_iter()
                                    .map(Into::into)
                                    .collect();
                                RuntimeTable { id, data: values }
                            })
                        })
                        .collect();

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
                    Ok(proof) => Ok(External::new([<NapiProof $field_name:camel>] {
                        proof,
                        public_input,
                    })),
                    Err(err) => Err(NapiError::new(Status::GenericFailure, err.to_string())),
                }
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_verify">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_verify>](
                index: $NapiVerifierIndex,
                proof: &External<NapiProofF>,
            ) -> bool {
                    let group_map = <$G as CommitmentCurve>::Map::setup();
                    let verifier_index = &index.into();
                    let (proof, public_input) = (&proof.as_ref().proof, &proof.as_ref().public_input);
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
                proofs: &External<Vec<NapiProofF>>,
            ) -> bool {
                let indexes: Vec<_> = indexes.into_iter().map(Into::into).collect();
                let proofs_ref = proofs.as_ref();

                if indexes.len() != proofs_ref.len() {
                    return false;
                }

                let contexts: Vec<_> = indexes
                    .iter()
                    .zip(proofs_ref.iter())
                    .map(|(index, proof)| Context {
                        verifier_index: index,
                        proof: &proof.proof,
                        public_input: &proof.public_input,
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
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_dummy>]() -> External<NapiProofF> {
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
                External::new(NapiProofF{proof: dlogproof, public_input: public})
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_deep_copy">])]
            pub fn [<caml_pasta_ $field_name:snake "_plonk_proof_deep_copy">](
                x: &External<NapiProofF>
            ) -> External<NapiProofF> {
                External::new(x.as_ref().clone())
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
        wrappers::{field::NapiPastaFp, group::NapiGVesta},
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
        Fp
    );
}

pub mod fq {
    use super::*;
    use crate::{
        pasta_fq_plonk_index::WasmPastaFqPlonkIndex as NapiPastaFqPlonkIndex,
        plonk_verifier_index::fq::NapiFqPlonkVerifierIndex,
        poly_comm::pallas::NapiFqPolyComm,
        wrappers::{field::NapiPastaFq, group::NapiGPallas},
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
        Fq
    );
}
