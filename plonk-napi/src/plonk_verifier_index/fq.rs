use serde::{Deserialize, Serialize};

use super::WasmLookupInfo;

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqDomain {
    pub log_size_of_group: i32,
    pub group_gen: Vec<u8>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqPolyComm {
    pub unshifted: Vec<Vec<u8>>,
    pub shifted: Option<Vec<u8>>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqShifts {
    pub s0: Vec<u8>,
    pub s1: Vec<u8>,
    pub s2: Vec<u8>,
    pub s3: Vec<u8>,
    pub s4: Vec<u8>,
    pub s5: Vec<u8>,
    pub s6: Vec<u8>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqLookupSelectors {
    pub xor: Option<WasmFqPolyComm>,
    pub lookup: Option<WasmFqPolyComm>,
    pub range_check: Option<WasmFqPolyComm>,
    pub ffmul: Option<WasmFqPolyComm>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqLookupVerifierIndex {
    pub joint_lookup_used: bool,
    pub lookup_table: Vec<WasmFqPolyComm>,
    pub lookup_selectors: WasmFqLookupSelectors,
    pub table_ids: Option<WasmFqPolyComm>,
    pub lookup_info: WasmLookupInfo,
    pub runtime_tables_selector: Option<WasmFqPolyComm>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqPlonkVerificationEvals {
    pub sigma_comm: Vec<WasmFqPolyComm>,
    pub coefficients_comm: Vec<WasmFqPolyComm>,
    pub generic_comm: WasmFqPolyComm,
    pub psm_comm: WasmFqPolyComm,
    pub complete_add_comm: WasmFqPolyComm,
    pub mul_comm: WasmFqPolyComm,
    pub emul_comm: WasmFqPolyComm,
    pub endomul_scalar_comm: WasmFqPolyComm,
    pub xor_comm: Option<WasmFqPolyComm>,
    pub range_check0_comm: Option<WasmFqPolyComm>,
    pub range_check1_comm: Option<WasmFqPolyComm>,
    pub foreign_field_add_comm: Option<WasmFqPolyComm>,
    pub foreign_field_mul_comm: Option<WasmFqPolyComm>,
    pub rot_comm: Option<WasmFqPolyComm>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqPlonkVerifierIndex {
    pub domain: WasmFqDomain,
    pub max_poly_size: i32,
    pub public_: i32,
    pub prev_challenges: i32,
    pub srs: Vec<u8>,
    pub evals: WasmFqPlonkVerificationEvals,
    pub shifts: WasmFqShifts,
    pub lookup_index: Option<WasmFqLookupVerifierIndex>,
    pub zk_rows: i32,
}
