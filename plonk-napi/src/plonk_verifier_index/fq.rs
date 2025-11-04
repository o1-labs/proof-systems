use crate::wrappers::lookups::NapiLookupInfo;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_serialize::CanonicalSerialize;
use kimchi::circuits::polynomials::permutation::Shifts as KimchiShifts;
use mina_curves::pasta::Fq;
use napi::bindgen_prelude::{Error, Result as NapiResult, Status};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqDomain {
    pub log_size_of_group: i32,
    pub group_gen: Vec<u8>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqPolyComm {
    pub unshifted: Vec<Vec<u8>>,
    pub shifted: Option<Vec<u8>>,
}

#[napi(object)]
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

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqLookupSelectors {
    pub xor: Option<WasmFqPolyComm>,
    pub lookup: Option<WasmFqPolyComm>,
    pub range_check: Option<WasmFqPolyComm>,
    pub ffmul: Option<WasmFqPolyComm>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFqLookupVerifierIndex {
    pub joint_lookup_used: bool,
    pub lookup_table: Vec<WasmFqPolyComm>,
    pub lookup_selectors: WasmFqLookupSelectors,
    pub table_ids: Option<WasmFqPolyComm>,
    pub lookup_info: NapiLookupInfo,
    pub runtime_tables_selector: Option<WasmFqPolyComm>,
}

#[napi(object)]
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

#[napi(object)]
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

#[napi]
pub fn caml_pasta_fq_plonk_verifier_index_shifts(log2_size: i32) -> NapiResult<WasmFqShifts> {
    println!(
        "from napi! caml_pasta_fp_plonk_verifier_index_shifts with log2_size {}",
        log2_size
    );

    let size = 1usize << (log2_size as u32);
    let domain = Domain::<Fq>::new(size)
        .ok_or_else(|| Error::new(Status::InvalidArg, "failed to create evaluation domain"))?;

    let shifts = KimchiShifts::new(&domain);
    let s = shifts.shifts();

    Ok(WasmFqShifts {
        s0: serialize_fp(&s[0])?,
        s1: serialize_fp(&s[1])?,
        s2: serialize_fp(&s[2])?,
        s3: serialize_fp(&s[3])?,
        s4: serialize_fp(&s[4])?,
        s5: serialize_fp(&s[5])?,
        s6: serialize_fp(&s[6])?,
    })
}

fn serialize_fp(value: &Fq) -> NapiResult<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .map_err(|err| Error::new(Status::GenericFailure, format!("serialize_fp: {err}")))?;
    Ok(bytes)
}
