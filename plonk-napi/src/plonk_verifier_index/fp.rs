use crate::{poly_comm::vesta::NapiFpPolyComm, wrappers::lookups::NapiLookupInfo};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_serialize::CanonicalSerialize;
use kimchi::circuits::polynomials::permutation::Shifts as KimchiShifts;
use mina_curves::pasta::Fp;
use napi::bindgen_prelude::{Error, Status};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WasmFpDomain {
    pub log_size_of_group: i32,
    pub group_gen: Vec<u8>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFpShifts {
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
pub struct NapiFpLookupSelectors {
    pub xor: Option<NapiFpPolyComm>,
    pub lookup: Option<NapiFpPolyComm>,
    pub range_check: Option<NapiFpPolyComm>,
    pub ffmul: Option<NapiFpPolyComm>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFpLookupVerifierIndex {
    pub joint_lookup_used: bool,
    pub lookup_table: Vec<NapiFpPolyComm>,
    pub lookup_selectors: NapiFpLookupSelectors,
    pub table_ids: Option<NapiFpPolyComm>,
    pub lookup_info: NapiLookupInfo,
    pub runtime_tables_selector: Option<NapiFpPolyComm>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFpPlonkVerificationEvals {
    pub sigma_comm: Vec<NapiFpPolyComm>,
    pub coefficients_comm: Vec<NapiFpPolyComm>,
    pub generic_comm: NapiFpPolyComm,
    pub psm_comm: NapiFpPolyComm,
    pub complete_add_comm: NapiFpPolyComm,
    pub mul_comm: NapiFpPolyComm,
    pub emul_comm: NapiFpPolyComm,
    pub endomul_scalar_comm: NapiFpPolyComm,
    pub xor_comm: Option<NapiFpPolyComm>,
    pub range_check0_comm: Option<NapiFpPolyComm>,
    pub range_check1_comm: Option<NapiFpPolyComm>,
    pub foreign_field_add_comm: Option<NapiFpPolyComm>,
    pub foreign_field_mul_comm: Option<NapiFpPolyComm>,
    pub rot_comm: Option<NapiFpPolyComm>,
}

#[napi(object)]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFpPlonkVerifierIndex {
    pub domain: WasmFpDomain,
    pub max_poly_size: i32,
    pub public_: i32,
    pub prev_challenges: i32,
    pub srs: Vec<u8>,
    pub evals: NapiFpPlonkVerificationEvals,
    pub shifts: NapiFpShifts,
    pub lookup_index: Option<NapiFpLookupVerifierIndex>,
    pub zk_rows: i32,
}

#[napi]
pub fn caml_pasta_fp_plonk_verifier_index_shifts(
    log2_size: i32,
) -> napi::bindgen_prelude::Result<NapiFpShifts> {
    println!(
        "from napi! caml_pasta_fp_plonk_verifier_index_shifts with log2_size {}",
        log2_size
    );

    let size = 1usize << (log2_size as u32);
    let domain = Domain::<Fp>::new(size)
        .ok_or_else(|| Error::new(Status::InvalidArg, "failed to create evaluation domain"))?;

    let shifts = KimchiShifts::new(&domain);
    let s = shifts.shifts();

    Ok(NapiFpShifts {
        s0: serialize_fp(&s[0])?,
        s1: serialize_fp(&s[1])?,
        s2: serialize_fp(&s[2])?,
        s3: serialize_fp(&s[3])?,
        s4: serialize_fp(&s[4])?,
        s5: serialize_fp(&s[5])?,
        s6: serialize_fp(&s[6])?,
    })
}

fn serialize_fp(value: &Fp) -> napi::bindgen_prelude::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|err| Error::new(Status::GenericFailure, format!("serialize_fp: {err}")))?;
    Ok(bytes)
}
