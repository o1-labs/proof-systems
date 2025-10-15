use std::sync::Arc;

use mina_curves::pasta::{Pallas as GAffineOther, Vesta as GAffine};
use napi::bindgen_prelude::{Error, External, Result as NapiResult, Status, Uint8Array};
use napi_derive::napi;
use plonk_wasm::srs::fp::WasmFpSrs as WasmSrsFp;
use plonk_wasm::srs::fq::WasmFqSrs as WasmSrsFq;

use poly_commitment::ipa::SRS;

#[napi]
pub fn caml_fp_srs_to_bytes(srs: External<WasmSrsFp>) -> NapiResult<Uint8Array> {
    let buffer = rmp_serde::to_vec(srs.as_ref().0.as_ref())
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Uint8Array::from(buffer))
}

#[napi]
pub fn caml_fp_srs_from_bytes(bytes: Uint8Array) -> NapiResult<External<WasmSrsFp>> {
    let srs: SRS<GAffine> = rmp_serde::from_slice(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(External::new(Arc::new(srs).into()))
}

#[napi]
pub fn caml_fq_srs_from_bytes(bytes: Uint8Array) -> NapiResult<External<WasmSrsFq>> {
    let srs: SRS<GAffineOther> = rmp_serde::from_slice(bytes.as_ref())
        .map_err(|e: rmp_serde::decode::Error| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(External::new(Arc::new(srs).into()))
}
