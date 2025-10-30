use serde::{Deserialize, Serialize};

use super::WasmLookupInfo;

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpDomain {
    pub log_size_of_group: i32,
    pub group_gen: Vec<u8>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpPolyComm {
    pub unshifted: Vec<Vec<u8>>,
    pub shifted: Option<Vec<u8>>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpShifts {
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
pub struct WasmFpLookupSelectors {
    pub xor: Option<WasmFpPolyComm>,
    pub lookup: Option<WasmFpPolyComm>,
    pub range_check: Option<WasmFpPolyComm>,
    pub ffmul: Option<WasmFpPolyComm>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpLookupVerifierIndex {
    pub joint_lookup_used: bool,
    pub lookup_table: Vec<WasmFpPolyComm>,
    pub lookup_selectors: WasmFpLookupSelectors,
    pub table_ids: Option<WasmFpPolyComm>,
    pub lookup_info: WasmLookupInfo,
    pub runtime_tables_selector: Option<WasmFpPolyComm>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpPlonkVerificationEvals {
    pub sigma_comm: Vec<WasmFpPolyComm>,
    pub coefficients_comm: Vec<WasmFpPolyComm>,
    pub generic_comm: WasmFpPolyComm,
    pub psm_comm: WasmFpPolyComm,
    pub complete_add_comm: WasmFpPolyComm,
    pub mul_comm: WasmFpPolyComm,
    pub emul_comm: WasmFpPolyComm,
    pub endomul_scalar_comm: WasmFpPolyComm,
    pub xor_comm: Option<WasmFpPolyComm>,
    pub range_check0_comm: Option<WasmFpPolyComm>,
    pub range_check1_comm: Option<WasmFpPolyComm>,
    pub foreign_field_add_comm: Option<WasmFpPolyComm>,
    pub foreign_field_mul_comm: Option<WasmFpPolyComm>,
    pub rot_comm: Option<WasmFpPolyComm>,
}

#[napi_derive::napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpPlonkVerifierIndex {
    pub domain: WasmFpDomain,
    pub max_poly_size: i32,
    pub public_: i32,
    pub prev_challenges: i32,
    pub srs: Vec<u8>,
    pub evals: WasmFpPlonkVerificationEvals,
    pub shifts: WasmFpShifts,
    pub lookup_index: Option<WasmFpLookupVerifierIndex>,
    pub zk_rows: i32,
}
