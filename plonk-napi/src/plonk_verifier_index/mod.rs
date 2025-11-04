use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmLookupPatterns {
    pub xor: bool,
    pub lookup: bool,
    pub range_check: bool,
    pub foreign_field_mul: bool,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmLookupFeatures {
    pub patterns: WasmLookupPatterns,
    pub joint_lookup_used: bool,
    pub uses_runtime_tables: bool,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmLookupInfo {
    pub max_per_row: i32,
    pub max_joint_size: i32,
    pub features: WasmLookupFeatures,
}

pub mod fp;
pub mod fq;

#[allow(unused_imports)]
pub use fp::*;
#[allow(unused_imports)]
pub use fq::*;
