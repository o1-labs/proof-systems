use napi::bindgen_prelude::*;
use napi::Error;
use napi_derive::napi;

use crate::build_info::report_native_call;

#[napi(js_name = "caml_pasta_fq_plonk_proof_create")]
pub fn caml_pasta_fq_plonk_proof_create(index: Uint8Array) -> Result<Uint8Array> {
    report_native_call();
    println!("caml_pasta_fq_plonk_proof_create from native rust");

    if index.len() > 100 {
        Ok(index)
    } else {
        Err(Error::from_reason("not implemented"))
    }
}
