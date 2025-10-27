use arkworks::{WasmPastaFp, WasmPastaFq};
use kimchi::circuits::lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use wasm_types::FlatVector;

fn bytes_to_fp_vec(bytes: Vec<u8>) -> Vec<Fp> {
    FlatVector::<WasmPastaFp>::from_bytes(bytes)
        .into_iter()
        .map(Into::into)
        .collect()
}

fn bytes_to_fq_vec(bytes: Vec<u8>) -> Vec<Fq> {
    FlatVector::<WasmPastaFq>::from_bytes(bytes)
        .into_iter()
        .map(Into::into)
        .collect()
}

fn typed_array_to_vec(array: &Uint8Array) -> Vec<u8> {
    array.to_vec()
}

#[napi(object)]
pub struct JsLookupTableFp {
    pub id: i32,
    pub data: Vec<Uint8Array>,
}

#[napi(object)]
pub struct JsLookupTableFq {
    pub id: i32,
    pub data: Vec<Uint8Array>,
}

#[napi(object)]
pub struct JsRuntimeTableCfgFp {
    pub id: i32,
    pub first_column: Uint8Array,
}

#[napi(object)]
pub struct JsRuntimeTableCfgFq {
    pub id: i32,
    pub first_column: Uint8Array,
}

pub fn lookup_table_fp_from_js(js: JsLookupTableFp) -> napi::Result<LookupTable<Fp>> {
    let mut data = Vec::with_capacity(js.data.len());
    for column in js.data {
        data.push(bytes_to_fp_vec(typed_array_to_vec(&column)));
    }
    Ok(LookupTable { id: js.id, data })
}

pub fn lookup_table_fq_from_js(js: JsLookupTableFq) -> napi::Result<LookupTable<Fq>> {
    let mut data = Vec::with_capacity(js.data.len());
    for column in js.data {
        data.push(bytes_to_fq_vec(typed_array_to_vec(&column)));
    }
    Ok(LookupTable { id: js.id, data })
}

pub fn runtime_table_cfg_fp_from_js(js: JsRuntimeTableCfgFp) -> napi::Result<RuntimeTableCfg<Fp>> {
    Ok(RuntimeTableCfg {
        id: js.id,
        first_column: bytes_to_fp_vec(typed_array_to_vec(&js.first_column)),
    })
}

pub fn runtime_table_cfg_fq_from_js(js: JsRuntimeTableCfgFq) -> napi::Result<RuntimeTableCfg<Fq>> {
    Ok(RuntimeTableCfg {
        id: js.id,
        first_column: bytes_to_fq_vec(typed_array_to_vec(&js.first_column)),
    })
}
