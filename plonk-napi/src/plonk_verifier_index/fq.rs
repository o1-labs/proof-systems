use crate::{poly_comm::pallas::NapiFqPolyComm, wrappers::lookups::NapiLookupInfo};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_serialize::CanonicalSerialize;
use kimchi::circuits::polynomials::permutation::Shifts as KimchiShifts;
use mina_curves::pasta::Fq;
use napi::bindgen_prelude::{Error, Status};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi(object, js_name = "WasmFqDomain")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqDomain {
    pub log_size_of_group: i32,
    pub group_gen: Vec<u8>,
}

#[napi(object, js_name = "WasmFqShifts")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqShifts {
    pub s0: Vec<u8>,
    pub s1: Vec<u8>,
    pub s2: Vec<u8>,
    pub s3: Vec<u8>,
    pub s4: Vec<u8>,
    pub s5: Vec<u8>,
    pub s6: Vec<u8>,
}

#[napi(object, js_name = "WasmFqLookupSelectors")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqLookupSelectors {
    pub xor: Option<NapiFqPolyComm>,
    pub lookup: Option<NapiFqPolyComm>,
    pub range_check: Option<NapiFqPolyComm>,
    pub ffmul: Option<NapiFqPolyComm>,
}

#[napi(object, js_name = "WasmFqLookupVerifierIndex")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqLookupVerifierIndex {
    pub joint_lookup_used: bool,
    pub lookup_table: Vec<NapiFqPolyComm>,
    pub lookup_selectors: NapiFqLookupSelectors,
    pub table_ids: Option<NapiFqPolyComm>,
    pub lookup_info: NapiLookupInfo,
    pub runtime_tables_selector: Option<NapiFqPolyComm>,
}

#[napi(object, js_name = "WasmFqPlonkVerificationEvals")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqPlonkVerificationEvals {
    pub sigma_comm: Vec<NapiFqPolyComm>,
    pub coefficients_comm: Vec<NapiFqPolyComm>,
    pub generic_comm: NapiFqPolyComm,
    pub psm_comm: NapiFqPolyComm,
    pub complete_add_comm: NapiFqPolyComm,
    pub mul_comm: NapiFqPolyComm,
    pub emul_comm: NapiFqPolyComm,
    pub endomul_scalar_comm: NapiFqPolyComm,
    pub xor_comm: Option<NapiFqPolyComm>,
    pub range_check0_comm: Option<NapiFqPolyComm>,
    pub range_check1_comm: Option<NapiFqPolyComm>,
    pub foreign_field_add_comm: Option<NapiFqPolyComm>,
    pub foreign_field_mul_comm: Option<NapiFqPolyComm>,
    pub rot_comm: Option<NapiFqPolyComm>,
}

#[napi(object, js_name = "WasmFqPlonkVerifierIndex")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqPlonkVerifierIndex {
    pub domain: NapiFqDomain,
    pub max_poly_size: i32,
    pub public_: i32,
    pub prev_challenges: i32,
    pub srs: Vec<u8>,
    pub evals: NapiFqPlonkVerificationEvals,
    pub shifts: NapiFqShifts,
    pub lookup_index: Option<NapiFqLookupVerifierIndex>,
    pub zk_rows: i32,
}

#[napi(js_name = "pasta_fq_plonk_verifier_index_shifts")]
pub fn caml_pasta_fq_plonk_verifier_index_shifts(
    log2_size: i32,
) -> napi::bindgen_prelude::Result<NapiFqShifts> {
    println!(
        "from napi! caml_pasta_fq_plonk_verifier_index_shifts with log2_size {}",
        log2_size
    );

    let size = 1usize << (log2_size as u32);
    let domain = Domain::<Fq>::new(size)
        .ok_or_else(|| Error::new(Status::InvalidArg, "failed to create evaluation domain"))?;

    let shifts = KimchiShifts::new(&domain);
    let s = shifts.shifts();

    Ok(NapiFqShifts {
        s0: serialize_fp(&s[0])?,
        s1: serialize_fp(&s[1])?,
        s2: serialize_fp(&s[2])?,
        s3: serialize_fp(&s[3])?,
        s4: serialize_fp(&s[4])?,
        s5: serialize_fp(&s[5])?,
        s6: serialize_fp(&s[6])?,
    })
}

fn serialize_fp(value: &Fq) -> napi::bindgen_prelude::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .map_err(|err| Error::new(Status::GenericFailure, format!("serialize_fp: {err}")))?;
    Ok(bytes)
}
