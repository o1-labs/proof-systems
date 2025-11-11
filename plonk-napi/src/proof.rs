use crate::{
    tables::{JsRuntimeTableFp, JsRuntimeTableFq},
    vector::{fp::NapiVecVecFp, fq::NapiVecVecFq, NapiFlatVector, NapiVector},
};
use ark_ec::AffineRepr;
use ark_ff::One;
use core::array;
use kimchi::{
    circuits::{lookup::runtime_tables::RuntimeTable, wires::COLUMNS},
    groupmap::GroupMap,
    proof::{
        PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof, RecursionChallenge,
    },
    prover_index::ProverIndex,
    verifier::{batch_verify, Context},
};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use napi::{
    bindgen_prelude::{External, Result},
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
     $field_name: ident
     ) => {
        paste! {
            #[derive(Clone)]
            pub struct [<NapiProof $field_name:camel>] {
                pub proof: ProverProof<$G, OpeningProof<$G>>,
                pub public_input: Vec<$F>,
            }

            /*
            pub struct [<Napi $field_name:camel ProofEvaluations>](
                ProofEvaluations<PointEvaluations<Vec<$F>>>
            );
            */

            //type NapiProofEvaluations = [<Napi $field_name:camel ProofEvaluations>];
            type NapiVecVecF = [<NapiVecVec $field_name:camel>];
            type JsRuntimeTableF = [<JsRuntimeTable $field_name:camel>];
            type NapiProofF = [<NapiProof $field_name:camel>];

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_proof_create">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_proof_create>](
                index: &External<$NapiIndex>,
                witness: NapiVecVecF,
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
        wrappers::{field::NapiPastaFp, group::NapiGVesta},
        NapiFpPlonkVerifierIndex,
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
        Fp
    );
}

pub mod fq {
    use super::*;
    use crate::{
        pasta_fq_plonk_index::WasmPastaFqPlonkIndex as NapiPastaFqPlonkIndex,
        wrappers::{field::NapiPastaFq, group::NapiGPallas},
        NapiFqPlonkVerifierIndex,
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
        Fq
    );
}
