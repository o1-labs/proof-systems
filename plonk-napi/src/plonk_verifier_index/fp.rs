use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_serialize::CanonicalSerialize;
use kimchi::circuits::polynomials::permutation::Shifts as KimchiShifts;
use mina_curves::pasta::Fp;
use napi::bindgen_prelude::{Error, Result as NapiResult, Status};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use super::WasmLookupInfo;

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpDomain {
    pub log_size_of_group: i32,
    pub group_gen: Vec<u8>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpPolyComm {
    pub unshifted: Vec<Vec<u8>>,
    pub shifted: Option<Vec<u8>>,
}

#[napi(object)]
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

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpLookupSelectors {
    pub xor: Option<WasmFpPolyComm>,
    pub lookup: Option<WasmFpPolyComm>,
    pub range_check: Option<WasmFpPolyComm>,
    pub ffmul: Option<WasmFpPolyComm>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpLookupVerifierIndex {
    pub joint_lookup_used: bool,
    pub lookup_table: Vec<WasmFpPolyComm>,
    pub lookup_selectors: WasmFpLookupSelectors,
    pub table_ids: Option<WasmFpPolyComm>,
    pub lookup_info: WasmLookupInfo,
    pub runtime_tables_selector: Option<WasmFpPolyComm>,
}

#[napi(object)]
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

#[napi(object)]
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

#[napi]
pub fn caml_pasta_fp_plonk_verifier_index_shifts(log2_size: i32) -> NapiResult<WasmFpShifts> {
    println!(
        "from napi! caml_pasta_fp_plonk_verifier_index_shifts with log2_size {}",
        log2_size
    );

    let size = 1usize << (log2_size as u32);
    let domain = Domain::<Fp>::new(size)
        .ok_or_else(|| Error::new(Status::InvalidArg, "failed to create evaluation domain"))?;

    let shifts = KimchiShifts::new(&domain);
    let s = shifts.shifts();

    Ok(WasmFpShifts {
        s0: serialize_fp(&s[0])?,
        s1: serialize_fp(&s[1])?,
        s2: serialize_fp(&s[2])?,
        s3: serialize_fp(&s[3])?,
        s4: serialize_fp(&s[4])?,
        s5: serialize_fp(&s[5])?,
        s6: serialize_fp(&s[6])?,
    })
}

fn serialize_fp(value: &Fp) -> NapiResult<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|err| Error::new(Status::GenericFailure, format!("serialize_fp: {err}")))?;
    Ok(bytes)
}
