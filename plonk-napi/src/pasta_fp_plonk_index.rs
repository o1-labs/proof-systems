use ark_poly::EvaluationDomain;
use kimchi::{linearization::expr_linearization, prover_index::ProverIndex};
use mina_curves::pasta::{Vesta as GAffine, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use napi::bindgen_prelude::{Error, External, Result as NapiResult, Status, Uint8Array};
use napi_derive::napi;
use poly_commitment::ipa::{OpeningProof, SRS as IPA_SRS};
use poly_commitment::SRS;
use serde::{Deserialize, Serialize};
use std::{io::Cursor, sync::Arc};
pub struct WasmPastaFpPlonkIndex(pub Box<ProverIndex<GAffine, OpeningProof<GAffine>>>);

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[derive(Serialize, Deserialize)]
struct SerializedProverIndex {
    prover_index: Vec<u8>,
    srs: Vec<u8>,
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
impl WasmPastaFpPlonkIndex {
    fn serialize_inner(&self) -> Result<Vec<u8>, String> {
        let prover_index = rmp_serde::to_vec(self.0.as_ref()).map_err(|e| e.to_string())?;

        let mut srs = Vec::new();
        self.0
            .srs
            .serialize(&mut rmp_serde::Serializer::new(&mut srs))
            .map_err(|e| e.to_string())?;

        let serialized = SerializedProverIndex { prover_index, srs };

        rmp_serde::to_vec(&serialized).map_err(|e| e.to_string())
    }

    fn deserialize_inner(bytes: &[u8]) -> Result<Self, String> {
        let serialized: SerializedProverIndex =
            rmp_serde::from_slice(bytes).map_err(|e| e.to_string())?;

        let mut index: ProverIndex<GAffine, OpeningProof<GAffine>> = ProverIndex::deserialize(
            &mut rmp_serde::Deserializer::new(Cursor::new(serialized.prover_index)),
        )
        .map_err(|e| e.to_string())?;

        let srs = IPA_SRS::<GAffine>::deserialize(&mut rmp_serde::Deserializer::new(Cursor::new(
            serialized.srs,
        )))
        .map_err(|e| e.to_string())?;

        index.srs = Arc::new(srs);

        let (linearization, powers_of_alpha) =
            expr_linearization(Some(&index.cs.feature_flags), true);
        index.linearization = linearization;
        index.powers_of_alpha = powers_of_alpha;

        index.compute_verifier_index_digest::<
            DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        >();

        Ok(WasmPastaFpPlonkIndex(Box::new(index)))
    }
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi]
pub fn prover_index_fp_from_bytes(
    bytes: Uint8Array,
) -> NapiResult<External<WasmPastaFpPlonkIndex>> {
    let index = WasmPastaFpPlonkIndex::deserialize_inner(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e))?;
    Ok(External::new(index))
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi]
pub fn prover_index_fp_to_bytes(index: External<WasmPastaFpPlonkIndex>) -> NapiResult<Uint8Array> {
    let bytes = index
        .serialize_inner()
        .map_err(|e| Error::new(Status::GenericFailure, e))?;
    Ok(Uint8Array::from(bytes))
}

#[napi]
pub fn caml_pasta_fp_plonk_index_max_degree(index: External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.srs.max_poly_size() as i32
}

#[napi]
pub fn caml_pasta_fp_plonk_index_public_inputs(index: External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.public as i32
}

#[napi]
pub fn caml_pasta_fp_plonk_index_domain_d1_size(index: External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.domain.d1.size() as i32
}

#[napi]
pub fn caml_pasta_fp_plonk_index_domain_d4_size(index: External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.domain.d4.size() as i32
}

#[napi]
pub fn caml_pasta_fp_plonk_index_domain_d8_size(index: External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.domain.d8.size() as i32
}
