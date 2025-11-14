use crate::{
    poly_comm::pallas::NapiFqPolyComm,
    srs::fq::NapiFqSrs,
    wrappers::{field::NapiPastaFq, lookups::NapiLookupInfo},
};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use kimchi::{
    circuits::{
        constraints::FeatureFlags,
        lookup::{
            index::LookupSelectors,
            lookups::{LookupFeatures, LookupPatterns},
        },
        polynomials::permutation::{
            permutation_vanishing_polynomial, zk_w, Shifts as KimchiShifts,
        },
    },
    linearization::expr_linearization,
    verifier_index::{LookupVerifierIndex, VerifierIndex as DlogVerifierIndex},
};
use mina_curves::pasta::{Fq, Pallas as GAffine, Vesta as GAffineOther};
use napi::bindgen_prelude::{Error, Status};
use napi_derive::napi;
use poly_commitment::{
    commitment::PolyComm,
    ipa::{OpeningProof, SRS},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[napi(object, js_name = "WasmFqDomain")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqDomain {
    pub log_size_of_group: i32,
    pub group_gen: NapiPastaFq,
}

#[napi(object, js_name = "WasmFqShifts")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqShifts {
    pub s0: NapiPastaFq,
    pub s1: NapiPastaFq,
    pub s2: NapiPastaFq,
    pub s3: NapiPastaFq,
    pub s4: NapiPastaFq,
    pub s5: NapiPastaFq,
    pub s6: NapiPastaFq,
}

#[napi(object, js_name = "WasmFqLookupSelectors")]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiFqLookupSelectors {
    pub xor: Option<NapiFqPolyComm>,
    pub lookup: Option<NapiFqPolyComm>,
    pub range_check: Option<NapiFqPolyComm>,
    pub ffmul: Option<NapiFqPolyComm>,
}

impl From<LookupSelectors<PolyComm<GAffine>>> for NapiFqLookupSelectors {
    fn from(x: LookupSelectors<PolyComm<GAffine>>) -> Self {
        Self {
            xor: x.xor.clone().map(Into::into),
            lookup: x.lookup.clone().map(Into::into),
            range_check: x.range_check.clone().map(Into::into),
            ffmul: x.ffmul.clone().map(Into::into),
        }
    }
}

impl From<&LookupSelectors<PolyComm<GAffine>>> for NapiFqLookupSelectors {
    fn from(x: &LookupSelectors<PolyComm<GAffine>>) -> Self {
        Self {
            xor: x.xor.clone().map(Into::into),
            lookup: x.lookup.clone().map(Into::into),
            range_check: x.range_check.clone().map(Into::into),
            ffmul: x.ffmul.clone().map(Into::into),
        }
    }
}

impl From<NapiFqLookupSelectors> for LookupSelectors<PolyComm<GAffine>> {
    fn from(x: NapiFqLookupSelectors) -> Self {
        Self {
            xor: x.xor.map(Into::into),
            lookup: x.lookup.map(Into::into),
            range_check: x.range_check.map(Into::into),
            ffmul: x.ffmul.map(Into::into),
        }
    }
}

impl From<&NapiFqLookupSelectors> for LookupSelectors<PolyComm<GAffine>> {
    fn from(x: &NapiFqLookupSelectors) -> Self {
        Self {
            xor: x.xor.clone().map(Into::into),
            lookup: x.lookup.clone().map(Into::into),
            range_check: x.range_check.clone().map(Into::into),
            ffmul: x.ffmul.clone().map(Into::into),
        }
    }
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

impl From<LookupVerifierIndex<GAffine>> for NapiFqLookupVerifierIndex {
    fn from(x: LookupVerifierIndex<GAffine>) -> Self {
        Self {
            joint_lookup_used: x.joint_lookup_used.into(),
            lookup_table: x.lookup_table.iter().map(Into::into).collect(),
            lookup_selectors: x.lookup_selectors.into(),
            table_ids: x.table_ids.map(Into::into),
            lookup_info: x.lookup_info.into(),
            runtime_tables_selector: x.runtime_tables_selector.map(Into::into),
        }
    }
}

impl From<&LookupVerifierIndex<GAffine>> for NapiFqLookupVerifierIndex {
    fn from(x: &LookupVerifierIndex<GAffine>) -> Self {
        Self {
            joint_lookup_used: x.joint_lookup_used.into(),
            lookup_table: x.lookup_table.clone().iter().map(Into::into).collect(),
            lookup_selectors: x.lookup_selectors.clone().into(),
            table_ids: x.table_ids.clone().map(Into::into),
            lookup_info: x.lookup_info.clone().into(),
            runtime_tables_selector: x.runtime_tables_selector.clone().map(Into::into),
        }
    }
}

impl From<&NapiFqLookupVerifierIndex> for LookupVerifierIndex<GAffine> {
    fn from(x: &NapiFqLookupVerifierIndex) -> Self {
        Self {
            joint_lookup_used: x.joint_lookup_used.into(),
            lookup_table: x.lookup_table.clone().iter().map(Into::into).collect(),
            lookup_selectors: x.lookup_selectors.clone().into(),
            table_ids: x.table_ids.clone().map(Into::into),
            lookup_info: x.lookup_info.clone().into(),
            runtime_tables_selector: x.runtime_tables_selector.clone().map(Into::into),
        }
    }
}

impl From<NapiFqLookupVerifierIndex> for LookupVerifierIndex<GAffine> {
    fn from(x: NapiFqLookupVerifierIndex) -> Self {
        Self {
            joint_lookup_used: x.joint_lookup_used.into(),
            lookup_table: x.lookup_table.iter().map(Into::into).collect(),
            lookup_selectors: x.lookup_selectors.into(),
            table_ids: x.table_ids.map(Into::into),
            lookup_info: x.lookup_info.into(),
            runtime_tables_selector: x.runtime_tables_selector.map(Into::into),
        }
    }
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
#[derive(Clone, Debug, Default)]
pub struct NapiFqPlonkVerifierIndex {
    pub domain: NapiFqDomain,
    pub max_poly_size: i32,
    pub public_: i32,
    pub prev_challenges: i32,
    pub srs: NapiFqSrs,
    pub evals: NapiFqPlonkVerificationEvals,
    pub shifts: NapiFqShifts,
    pub lookup_index: Option<NapiFqLookupVerifierIndex>,
    pub zk_rows: i32,
}

#[napi(js_name = "caml_pasta_fq_plonk_verifier_index_shifts")]
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
        s0: s[0].clone().into(),
        s1: s[1].clone().into(),
        s2: s[2].clone().into(),
        s3: s[3].clone().into(),
        s4: s[4].clone().into(),
        s5: s[5].clone().into(),
        s6: s[6].clone().into(),
    })
}

impl From<NapiFqPlonkVerifierIndex> for DlogVerifierIndex<GAffine, OpeningProof<GAffine>> {
    fn from(index: NapiFqPlonkVerifierIndex) -> Self {
        let max_poly_size = index.max_poly_size;
        let public_ = index.public_;
        let prev_challenges = index.prev_challenges;
        let log_size_of_group = index.domain.log_size_of_group;
        let srs = &index.srs;
        let evals = &index.evals;
        let shifts = &index.shifts;

        let (endo_q, _endo_r) = poly_commitment::ipa::endos::<GAffineOther>();
        let domain = Domain::<Fq>::new(1 << log_size_of_group).unwrap();

        let feature_flags = compute_feature_flags(&index);
        let (linearization, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);

        let index = {
            let zk_rows = index.zk_rows as u64;

            DlogVerifierIndex {
                domain,

                sigma_comm: core::array::from_fn(|i| (&evals.sigma_comm[i]).into()),
                generic_comm: (&evals.generic_comm).into(),
                coefficients_comm: core::array::from_fn(|i| (&evals.coefficients_comm[i]).into()),

                psm_comm: (&evals.psm_comm).into(),

                complete_add_comm: (&evals.complete_add_comm).into(),
                mul_comm: (&evals.mul_comm).into(),
                emul_comm: (&evals.emul_comm).into(),

                endomul_scalar_comm: (&evals.endomul_scalar_comm).into(),
                xor_comm: (&evals.xor_comm).as_ref().map(Into::into),
                range_check0_comm: (&evals.range_check0_comm).as_ref().map(Into::into),
                range_check1_comm: (&evals.range_check1_comm).as_ref().map(Into::into),
                foreign_field_add_comm: (&evals.foreign_field_add_comm).as_ref().map(Into::into),
                foreign_field_mul_comm: (&evals.foreign_field_mul_comm).as_ref().map(Into::into),
                rot_comm: (&evals.rot_comm).as_ref().map(Into::into),

                w: {
                    let res = once_cell::sync::OnceCell::new();
                    res.set(zk_w(domain, zk_rows)).unwrap();
                    res
                },
                endo: endo_q,
                max_poly_size: max_poly_size as usize,
                public: public_ as usize,
                prev_challenges: prev_challenges as usize,
                permutation_vanishing_polynomial_m: {
                    let res = once_cell::sync::OnceCell::new();
                    res.set(permutation_vanishing_polynomial(domain, zk_rows))
                        .unwrap();
                    res
                },
                shift: [
                    shifts.s0.into(),
                    shifts.s1.into(),
                    shifts.s2.into(),
                    shifts.s3.into(),
                    shifts.s4.into(),
                    shifts.s5.into(),
                    shifts.s6.into(),
                ],
                srs: { Arc::clone(&srs.0) },

                zk_rows,

                linearization,
                powers_of_alpha,
                lookup_index: index.lookup_index.map(Into::into),
            }
        };
        (index, srs.0.clone()).0
    }
}

fn compute_feature_flags(index: &NapiFqPlonkVerifierIndex) -> FeatureFlags {
    let xor = index.evals.xor_comm.is_some();
    let range_check0 = index.evals.range_check0_comm.is_some();
    let range_check1 = index.evals.range_check1_comm.is_some();
    let foreign_field_add = index.evals.foreign_field_add_comm.is_some();
    let foreign_field_mul = index.evals.foreign_field_mul_comm.is_some();
    let rot = index.evals.rot_comm.is_some();

    let lookup = index
        .lookup_index
        .as_ref()
        .map_or(false, |li| li.lookup_info.features.patterns.lookup);

    let runtime_tables = index
        .lookup_index
        .as_ref()
        .map_or(false, |li| li.runtime_tables_selector.is_some());

    let patterns = LookupPatterns {
        xor,
        lookup,
        range_check: range_check0 || range_check1 || rot,
        foreign_field_mul,
    };

    FeatureFlags {
        range_check0,
        range_check1,
        foreign_field_add,
        foreign_field_mul,
        xor,
        rot,
        lookup_features: LookupFeatures {
            patterns,
            joint_lookup_used: patterns.joint_lookups_used(),
            uses_runtime_tables: runtime_tables,
        },
    }
}
