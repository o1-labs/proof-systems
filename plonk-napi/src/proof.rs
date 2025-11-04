use crate::{
    tables::JsRuntimeTableFp,
    wasm_vector::{fp::WasmVecVecFp, WasmVector},
};
use arkworks::{WasmGVesta, WasmPastaFp};
use kimchi::error::ProverError;
use kimchi::{
    circuits::{lookup::runtime_tables::RuntimeTable, wires::COLUMNS},
    groupmap::GroupMap,
    proof::{ProverProof, RecursionChallenge},
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Vesta as GAffine};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use napi::bindgen_prelude::External;
use napi_derive::napi;
use plonk_wasm::{pasta_fp_plonk_index::WasmPastaFpPlonkIndex, plonk_proof};
use poly_commitment::{ipa::OpeningProof, PolyComm, SRS};
use wasm_types::FlatVector as WasmFlatVector;

#[napi]
pub fn caml_pasta_fp_plonk_proof_create(
    index: External<WasmPastaFpPlonkIndex>,
    witness: WasmVecVecFp,
    runtime_tables: WasmVector<JsRuntimeTableFp>,
    prev_challenges: WasmFlatVector<Fp>,
    prev_sgs: WasmVector<WasmGVesta>,
) -> Result<plonk_proof::fp::WasmFpProverProof, ProverError> {
    let (maybe_proof, public_input) = {
        index
            .0
            .srs
            .as_ref()
            .get_lagrange_basis(index.0.as_ref().cs.domain.d1);
        let prev: Vec<RecursionChallenge<GAffine>> = {
            if prev_challenges.is_empty() {
                Vec::new()
            } else {
                let challenges_per_sg = prev_challenges.len() / prev_sgs.len();
                let d = prev_sgs
                    .into_iter()
                    .map(Into::<GAffine>::into)
                    .enumerate()
                    .map(|(i, sg)| {
                        let chals = prev_challenges
                            [(i * challenges_per_sg)..(i + 1) * challenges_per_sg]
                            .iter()
                            .map(|a| a.clone().into())
                            .collect();
                        let comm = PolyComm::<GAffine> { chunks: vec![sg] };
                        RecursionChallenge { chals, comm }
                    })
                    .collect();
                d
            }
        };

        let rust_runtime_tables: Vec<RuntimeTable<Fp>> = runtime_tables
            .into_iter()
            .flat_map(|table| {
                let JsRuntimeTableFp { id, data } = table;
                data.into_iter().map(move |column| {
                    let values = WasmFlatVector::<WasmPastaFp>::from_bytes(column.to_vec())
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

        let index: &ProverIndex<GAffine, OpeningProof<GAffine>> = &index.0.as_ref();

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

    return match maybe_proof {
        Ok(proof) => Ok((proof, public_input).into()),
        Err(err) => Err(err),
    };
}
