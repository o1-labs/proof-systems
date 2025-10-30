use napi::bindgen_prelude::*;
use napi::Error;
use napi_derive::napi;

#[napi(js_name = "caml_pasta_fq_plonk_proof_create")]
pub fn caml_pasta_fq_plonk_proof_create(index: Uint8Array) -> Result<Uint8Array> {
    println!("caml_pasta_fq_plonk_proof_create from native rust");

    if index.len() > 100 {
        Ok(index)
    } else {
        Err(Error::from_reason("not implemented"))
    }
}
