use crate::wrappers::field::{WasmPastaFp, WasmPastaFq};
use mina_curves::pasta::{Fp, Fq};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, permutation::poseidon_block_cipher};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use wasm_types::{FlatVector, FlatVectorElem};

// fp

#[napi]
pub fn caml_pasta_fp_poseidon_block_cipher(state: Uint8Array) -> Result<Vec<u8>> {
    let mut state: Vec<Fp> = FlatVector::<WasmPastaFp>::from_bytes(state.to_vec())
        .into_iter()
        .map(Into::into)
        .collect();

    poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi>(
        mina_poseidon::pasta::fp_kimchi::static_params(),
        &mut state,
    );

    let res = state
        .into_iter()
        .map(WasmPastaFp)
        .flat_map(FlatVectorElem::flatten)
        .collect();

    Ok(res)
}

// fq

#[napi]
pub fn caml_pasta_fq_poseidon_block_cipher(state: Uint8Array) -> Result<Vec<u8>> {
    let mut state: Vec<Fq> = FlatVector::<WasmPastaFq>::from_bytes(state.to_vec())
        .into_iter()
        .map(Into::into)
        .collect();

    poseidon_block_cipher::<Fq, PlonkSpongeConstantsKimchi>(
        mina_poseidon::pasta::fq_kimchi::static_params(),
        &mut state,
    );

    let res = state
        .into_iter()
        .map(WasmPastaFq)
        .flat_map(FlatVectorElem::flatten)
        .collect();

    Ok(res)
}
