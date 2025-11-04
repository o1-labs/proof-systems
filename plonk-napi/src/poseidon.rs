use crate::wrappers::field::{NapiPastaFp, NapiPastaFq};
use mina_curves::pasta::{Fp, Fq};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, permutation::poseidon_block_cipher};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use wasm_types::{FlatVector, FlatVectorElem};

use crate::build_info::report_native_call;

// fp

#[napi(js_name = "caml_pasta_fp_poseidon_block_cipher")]
pub fn caml_pasta_fp_poseidon_block_cipher(state: Uint8Array) -> Result<Uint8Array> {
    report_native_call();

    println!("from native rust");

    let mut state_vec: Vec<Fp> = FlatVector::<NapiPastaFp>::from_bytes(state.to_vec())
        .into_iter()
        .map(Into::into)
        .collect();

    poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi>(
        mina_poseidon::pasta::fp_kimchi::static_params(),
        &mut state_vec,
    );

    let res: Vec<u8> = state_vec
        .into_iter()
        .map(NapiPastaFp)
        .flat_map(FlatVectorElem::flatten)
        .collect();

    Ok(Uint8Array::from(res))
}

// fq

#[napi(js_name = "caml_pasta_fq_poseidon_block_cipher")]
pub fn caml_pasta_fq_poseidon_block_cipher(state: Uint8Array) -> Result<Uint8Array> {
    report_native_call();

    println!("from native rust");

    let mut state_vec: Vec<Fq> = FlatVector::<NapiPastaFq>::from_bytes(state.to_vec())
        .into_iter()
        .map(Into::into)
        .collect();

    poseidon_block_cipher::<Fq, PlonkSpongeConstantsKimchi>(
        mina_poseidon::pasta::fq_kimchi::static_params(),
        &mut state_vec,
    );

    let res: Vec<u8> = state_vec
        .into_iter()
        .map(NapiPastaFq)
        .flat_map(FlatVectorElem::flatten)
        .collect();

    Ok(Uint8Array::from(res))
}
