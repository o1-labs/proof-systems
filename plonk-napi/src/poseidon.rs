use crate::wrappers::field::{WasmPastaFp, WasmPastaFq};
use mina_curves::pasta::{Fp, Fq};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, permutation::poseidon_block_cipher};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use wasm_types::{FlatVector, FlatVectorElem};

// fp

#[napi]
pub fn caml_pasta_fp_poseidon_block_cipher(state: Uint8Array) -> Result<Uint8Array> {
    let mut state_vec: Vec<Fp> = FlatVector::<WasmPastaFp>::from_bytes(state.to_vec())
        .into_iter()
        .map(Into::into)
        .collect();

    poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi>(
        mina_poseidon::pasta::fp_kimchi::static_params(),
        &mut state_vec,
    );

    let res: Vec<u8> = state_vec
        .into_iter()
        .map(WasmPastaFp)
        .flat_map(FlatVectorElem::flatten)
        .collect();

    Ok(Uint8Array::from(res))
}

// fq

#[napi]
pub fn caml_pasta_fq_poseidon_block_cipher(state: Uint8Array) -> Result<Uint8Array> {
    let mut state_vec: Vec<Fq> = FlatVector::<WasmPastaFq>::from_bytes(state.to_vec())
        .into_iter()
        .map(Into::into)
        .collect();

    poseidon_block_cipher::<Fq, PlonkSpongeConstantsKimchi>(
        mina_poseidon::pasta::fq_kimchi::static_params(),
        &mut state_vec,
    );

    let res: Vec<u8> = state_vec
        .into_iter()
        .map(WasmPastaFq)
        .flat_map(FlatVectorElem::flatten)
        .collect();

    Ok(Uint8Array::from(res))
}
