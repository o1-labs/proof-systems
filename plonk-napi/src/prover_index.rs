use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::types::WasmPastaFpPlonkIndex;

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi]
pub fn prover_index_from_bytes(bytes: Uint8Array) -> Result<External<WasmPastaFpPlonkIndex>> {
    let index = WasmPastaFpPlonkIndex::deserialize_inner(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e))?;
    Ok(External::new(index))
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi]
pub fn prover_index_to_bytes(index: &External<WasmPastaFpPlonkIndex>) -> Result<Uint8Array> {
    let bytes = index
        .serialize_inner()
        .map_err(|e| Error::new(Status::GenericFailure, e))?;
    Ok(Uint8Array::from(bytes))
}
