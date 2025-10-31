use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::{build_info::report_native_call, types::WasmPastaFpPlonkIndex};

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi(js_name = "prover_index_from_bytes")]
pub fn prover_index_from_bytes(bytes: Uint8Array) -> Result<External<WasmPastaFpPlonkIndex>> {
    report_native_call();

    let index = WasmPastaFpPlonkIndex::deserialize_inner(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e))?;
    Ok(External::new(index))
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi(js_name = "prover_index_to_bytes")]
pub fn prover_index_to_bytes(index: &External<WasmPastaFpPlonkIndex>) -> Result<Uint8Array> {
    report_native_call();

    let bytes = index
        .serialize_inner()
        .map_err(|e| Error::new(Status::GenericFailure, e))?;
    Ok(Uint8Array::from(bytes))
}
