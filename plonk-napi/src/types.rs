use kimchi::{linearization::expr_linearization, prover_index::ProverIndex};
use mina_curves::pasta::{Vesta as GAffine, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};

use poly_commitment::ipa::{OpeningProof, SRS};
use serde::{Deserialize, Serialize};
use std::{io::Cursor, sync::Arc};

pub struct WasmPastaFpPlonkIndex(pub Box<ProverIndex<GAffine, OpeningProof<GAffine>>>);

// TODO: remove incl all dependencies when no longer needed and we only pass napi objects around
#[derive(Serialize, Deserialize)]
struct SerializedProverIndex {
    prover_index: Vec<u8>,
    srs: Vec<u8>,
}

// TODO: remove incl all dependencies when no longer needed and we only pass napi objects around
impl WasmPastaFpPlonkIndex {
    pub(crate) fn serialize_inner(&self) -> Result<Vec<u8>, String> {
        let prover_index = rmp_serde::to_vec(self.0.as_ref()).map_err(|e| e.to_string())?;

        let mut srs = Vec::new();
        self.0
            .srs
            .serialize(&mut rmp_serde::Serializer::new(&mut srs))
            .map_err(|e| e.to_string())?;

        let serialized = SerializedProverIndex { prover_index, srs };

        rmp_serde::to_vec(&serialized).map_err(|e| e.to_string())
    }

    pub(crate) fn deserialize_inner(bytes: &[u8]) -> Result<Self, String> {
        let serialized: SerializedProverIndex =
            rmp_serde::from_slice(bytes).map_err(|e| e.to_string())?;

        let mut index: ProverIndex<GAffine, OpeningProof<GAffine>> = ProverIndex::deserialize(
            &mut rmp_serde::Deserializer::new(Cursor::new(serialized.prover_index)),
        )
        .map_err(|e| e.to_string())?;

        let srs = SRS::<GAffine>::deserialize(&mut rmp_serde::Deserializer::new(Cursor::new(
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
