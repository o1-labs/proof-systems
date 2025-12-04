mod build_info;
mod circuit;
mod gate_vector;
mod oracles;
mod pasta_fp_plonk_index;
mod pasta_fq_plonk_index;
mod plonk_verifier_index;
mod poly_comm;
mod poseidon;
mod proof;
mod srs;
mod tables;
mod vector;
mod wrappers;

pub use build_info::{get_native_calls, ARCH_NAME, BACKING, OS_NAME};

pub use circuit::prover_to_json;
pub use gate_vector::{
    caml_pasta_fp_plonk_circuit_serialize, caml_pasta_fp_plonk_gate_vector_add,
    caml_pasta_fp_plonk_gate_vector_create, caml_pasta_fp_plonk_gate_vector_digest,
    caml_pasta_fp_plonk_gate_vector_from_bytes,
    caml_pasta_fp_plonk_gate_vector_from_bytes_external, caml_pasta_fp_plonk_gate_vector_get,
    caml_pasta_fp_plonk_gate_vector_len, caml_pasta_fp_plonk_gate_vector_to_bytes,
    caml_pasta_fp_plonk_gate_vector_wrap, caml_pasta_fq_plonk_circuit_serialize,
    caml_pasta_fq_plonk_gate_vector_add, caml_pasta_fq_plonk_gate_vector_create,
    caml_pasta_fq_plonk_gate_vector_digest, caml_pasta_fq_plonk_gate_vector_from_bytes,
    caml_pasta_fq_plonk_gate_vector_from_bytes_external, caml_pasta_fq_plonk_gate_vector_get,
    caml_pasta_fq_plonk_gate_vector_len, caml_pasta_fq_plonk_gate_vector_to_bytes,
    caml_pasta_fq_plonk_gate_vector_wrap, NapiFpGate as WasmFpGate,
    NapiFpGateVector as WasmFpGateVector, NapiFqGate as WasmFqGate,
    NapiFqGateVector as WasmFqGateVector,
};
pub use oracles::{
    fp::{fp_oracles_create, fp_oracles_deep_copy, fp_oracles_dummy},
    fq::{fq_oracles_create, fq_oracles_deep_copy, fq_oracles_dummy},
};
pub use pasta_fp_plonk_index::{
    prover_index_fp_deserialize, prover_index_fp_serialize, WasmPastaFpPlonkIndex,
};
pub use pasta_fq_plonk_index::{
    prover_index_fq_deserialize, prover_index_fq_serialize, WasmPastaFqPlonkIndex,
};
pub use plonk_verifier_index::{
    fp::{
        caml_pasta_fp_plonk_verifier_index_create, caml_pasta_fp_plonk_verifier_index_deep_copy,
        caml_pasta_fp_plonk_verifier_index_deserialize, caml_pasta_fp_plonk_verifier_index_dummy,
        caml_pasta_fp_plonk_verifier_index_read, caml_pasta_fp_plonk_verifier_index_serialize,
        caml_pasta_fp_plonk_verifier_index_shifts, caml_pasta_fp_plonk_verifier_index_write,
    },
    fq::{
        caml_pasta_fq_plonk_verifier_index_create, caml_pasta_fq_plonk_verifier_index_deep_copy,
        caml_pasta_fq_plonk_verifier_index_deserialize, caml_pasta_fq_plonk_verifier_index_dummy,
        caml_pasta_fq_plonk_verifier_index_read, caml_pasta_fq_plonk_verifier_index_serialize,
        caml_pasta_fq_plonk_verifier_index_shifts, caml_pasta_fq_plonk_verifier_index_write,
    },
};

pub use poly_comm::{
    pallas::NapiFqPolyComm as WasmFqPolyComm, vesta::NapiFpPolyComm as WasmFpPolyComm,
};
pub use poseidon::{caml_pasta_fp_poseidon_block_cipher, caml_pasta_fq_poseidon_block_cipher};
pub use proof::{
    fp::{
        caml_pasta_fp_plonk_proof_batch_verify, caml_pasta_fp_plonk_proof_create,
        caml_pasta_fp_plonk_proof_deep_copy, caml_pasta_fp_plonk_proof_dummy,
        caml_pasta_fp_plonk_proof_verify, NapiFpLookupCommitments, NapiFpOpeningProof,
        NapiFpProofEvaluations, NapiFpProverCommitments, NapiFpProverProof,
    },
    fq::{
        caml_pasta_fq_plonk_proof_batch_verify, caml_pasta_fq_plonk_proof_create,
        caml_pasta_fq_plonk_proof_deep_copy, caml_pasta_fq_plonk_proof_dummy,
        caml_pasta_fq_plonk_proof_verify, NapiFqLookupCommitments, NapiFqOpeningProof,
        NapiFqProofEvaluations, NapiFqProverCommitments, NapiFqProverProof,
    },
};
pub use srs::{
    caml_fp_srs_from_bytes, caml_fp_srs_from_bytes_external, caml_fp_srs_to_bytes,
    caml_fp_srs_to_bytes_external, caml_fq_srs_from_bytes, caml_fq_srs_from_bytes_external,
    caml_fq_srs_to_bytes, caml_fq_srs_to_bytes_external, fp::NapiFpSrs as WasmFpSrs,
    fq::NapiFqSrs as WasmFqSrs, *,
};
pub use tables::{JsLookupTableFp, JsLookupTableFq, JsRuntimeTableCfgFp, JsRuntimeTableCfgFq};
pub use vector::{
    fp::NapiVecVecFp as WasmVecVecFp, fq::NapiVecVecFq as WasmVecVecFq, NapiFlatVector,
};
pub use wrappers::{
    field::{NapiPastaFp as WasmPastaFp, NapiPastaFq as WasmPastaFq},
    group::{NapiGPallas as WasmGPallas, NapiGVesta as WasmGVesta},
};

pub use plonk_verifier_index::{fp::*, fq::*};
