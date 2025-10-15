mod circuit;
mod gate_vector;
mod pasta_fp_plonk_index;
mod pasta_fq_plonk_index;
mod poseidon;
mod srs;
mod tables;

pub use gate_vector::{
    caml_pasta_fp_plonk_circuit_serialize, caml_pasta_fp_plonk_gate_vector_add,
    caml_pasta_fp_plonk_gate_vector_create, caml_pasta_fp_plonk_gate_vector_digest,
    caml_pasta_fp_plonk_gate_vector_from_bytes, caml_pasta_fp_plonk_gate_vector_get,
    caml_pasta_fp_plonk_gate_vector_len, caml_pasta_fp_plonk_gate_vector_to_bytes,
    caml_pasta_fp_plonk_gate_vector_wrap, caml_pasta_fq_plonk_circuit_serialize,
    caml_pasta_fq_plonk_gate_vector_add, caml_pasta_fq_plonk_gate_vector_create,
    caml_pasta_fq_plonk_gate_vector_digest, caml_pasta_fq_plonk_gate_vector_from_bytes,
    caml_pasta_fq_plonk_gate_vector_get, caml_pasta_fq_plonk_gate_vector_len,
    caml_pasta_fq_plonk_gate_vector_wrap, GateVectorHandleFp, GateVectorHandleFq, JsGateFp,
    JsGateFq, JsGateWires, JsWire,
};

pub use tables::{JsLookupTableFp, JsLookupTableFq, JsRuntimeTableCfgFp, JsRuntimeTableCfgFq};

pub use srs::{caml_fp_srs_from_bytes, caml_fp_srs_to_bytes, caml_fq_srs_from_bytes};

pub use poseidon::{caml_pasta_fp_poseidon_block_cipher, caml_pasta_fq_poseidon_block_cipher};

pub use circuit::prover_to_json;
pub use pasta_fp_plonk_index::{
    prover_index_fp_from_bytes, prover_index_fp_to_bytes, WasmPastaFpPlonkIndex,
};

pub use pasta_fq_plonk_index::{
    prover_index_fq_from_bytes, prover_index_fq_to_bytes, WasmPastaFqPlonkIndex,
};
