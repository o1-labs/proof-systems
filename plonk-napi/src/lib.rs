pub(crate) mod gate_vector;
pub(crate) mod poly_comm;
pub(crate) mod poseidon;
pub(crate) mod wasm_vector;
pub(crate) mod wrappers;

pub use poseidon::{caml_pasta_fp_poseidon_block_cipher, caml_pasta_fq_poseidon_block_cipher};

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
pub use poly_comm::{pallas::WasmFqPolyComm, vesta::WasmFpPolyComm};
pub use wasm_vector::{fp::WasmVecVecFp, fq::WasmVecVecFq};
pub use wrappers::group::{WasmGPallas, WasmGVesta};
