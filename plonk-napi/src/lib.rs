mod circuit;
mod gate_vector;
mod pasta_fp_plonk_index;
mod pasta_fq_plonk_index;
mod poly_comm;
mod poseidon;
mod types;
mod wrappers;
mod wasm_vector;

pub use circuit::prover_to_json;
pub use gate_vector::{
    caml_pasta_fp_plonk_circuit_serialize, caml_pasta_fp_plonk_gate_vector_add,
    caml_pasta_fp_plonk_gate_vector_create, caml_pasta_fp_plonk_gate_vector_digest,
    caml_pasta_fp_plonk_gate_vector_get, caml_pasta_fp_plonk_gate_vector_len,
    caml_pasta_fp_plonk_gate_vector_wrap, caml_pasta_fq_plonk_circuit_serialize,
    caml_pasta_fq_plonk_gate_vector_add, caml_pasta_fq_plonk_gate_vector_create,
    caml_pasta_fq_plonk_gate_vector_digest, caml_pasta_fq_plonk_gate_vector_get,
    caml_pasta_fq_plonk_gate_vector_len, caml_pasta_fq_plonk_gate_vector_wrap,
    NapiFpGate as WasmFpGate, NapiFpGateVector as WasmFpGateVector, NapiFqGate as WasmFqGate,
    NapiFqGateVector as WasmFqGateVector,
};
pub use pasta_fp_plonk_index::{
    prover_index_fp_from_bytes, prover_index_fp_to_bytes, WasmPastaFpPlonkIndex,
};
pub use pasta_fq_plonk_index::{
    prover_index_fq_from_bytes, prover_index_fq_to_bytes, WasmPastaFqPlonkIndex,
};
pub use poly_comm::{pallas::WasmFqPolyComm, vesta::WasmFpPolyComm};
pub use poseidon::{caml_pasta_fp_poseidon_block_cipher, caml_pasta_fq_poseidon_block_cipher};
pub use wasm_vector::{fp::WasmVecVecFp, fq::WasmVecVecFq};
pub use wrappers::{field::{WasmPastaFp, WasmPastaFq}, group::{WasmGPallas, WasmGVesta}};
