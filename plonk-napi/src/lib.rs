mod circuit;
mod pasta_fp_plonk_index;
mod pasta_fq_plonk_index;
mod srs;
mod tables;

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
pub(crate) mod poly_comm;
pub(crate) mod poseidon;
pub(crate) mod wasm_vector;
pub(crate) mod wrappers;

pub use poly_comm::{pallas::WasmFqPolyComm, vesta::WasmFpPolyComm};
pub use wasm_vector::{fp::WasmVecVecFp, fq::WasmVecVecFq};
pub use wrappers::group::{WasmGPallas, WasmGVesta};
