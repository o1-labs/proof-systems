use crate::{vector::NapiVector, wrappers::lookups::NapiLookupInfo};
use ark_ec::AffineRepr;
use ark_ff::One;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use kimchi::{
    circuits::{
        constraints::FeatureFlags,
        lookup::{
            index::LookupSelectors,
            lookups::{LookupFeatures, LookupPatterns},
        },
        polynomials::permutation::{permutation_vanishing_polynomial, zk_w, Shifts},
        wires::{COLUMNS, PERMUTS},
    },
    linearization::expr_linearization,
    verifier_index::{LookupVerifierIndex, VerifierIndex},
};
use napi::{bindgen_prelude::*, Error, Status};
use napi_derive::napi;
use paste::paste;
use poly_commitment::{
    commitment::PolyComm,
    ipa::{OpeningProof, SRS},
    SRS as _,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

macro_rules! impl_verification_key {
    (
     $NapiG: ty,
     $G: ty,
     $NapiF: ty,
     $F: ty,
     $NapiPolyComm: ty,
     $NapiSrs: ty,
     $GOther: ty,
     $FrSpongeParams: path,
     $FqSpongeParams: path,
     $NapiIndex: ty,
     $field_name: ident
     ) => {
        paste! {
            #[napi(object, js_name = [<Wasm $field_name:camel Domain>])]
            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            pub struct [<Napi $field_name:camel Domain>] {
                #[napi(js_name = "log_size_of_group")]
                pub log_size_of_group: i32,
                #[napi(js_name = "group_gen")]
                pub group_gen: $NapiF,
            }
            type NapiDomain = [<Napi $field_name:camel Domain>];

            impl From<NapiDomain> for Domain<[<$F>]> {
                fn from(domain: NapiDomain) -> Self {
                    let size = 1 << domain.log_size_of_group;
                    Domain::<[<$F>]>::new(size).expect("Failed to create evaluation domain")
                }
            }

            impl From<&Domain<$F>> for NapiDomain {
                fn from(domain: &Domain<$F>) -> Self {
                    Self {
                        log_size_of_group: domain.log_size_of_group as i32,
                        group_gen: domain.group_gen.into(),
                    }
                }
            }

            #[napi(object, js_name = [<Wasm $field_name:camel PlonkVerificationEvals>])]
            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            pub struct [<Napi $field_name:camel PlonkVerificationEvals>] {
                #[napi(js_name = "sigma_comm")]
                pub sigma_comm: NapiVector<$NapiPolyComm>,
                #[napi(js_name = "coefficients_comm")]
                pub coefficients_comm: NapiVector<$NapiPolyComm>,
                #[napi(js_name = "generic_comm")]
                pub generic_comm: $NapiPolyComm,
                #[napi(js_name = "psm_comm")]
                pub psm_comm: $NapiPolyComm,
                #[napi(js_name = "complete_add_comm")]
                pub complete_add_comm: $NapiPolyComm,
                #[napi(js_name = "mul_comm")]
                pub mul_comm: $NapiPolyComm,
                #[napi(js_name = "emul_comm")]
                pub emul_comm: $NapiPolyComm,
                #[napi(js_name = "endomul_scalar_comm")]
                pub endomul_scalar_comm: $NapiPolyComm,
                #[napi(js_name = "xor_comm")]
                pub xor_comm: Option<$NapiPolyComm>,
                #[napi(js_name = "range_check0_comm")]
                pub range_check0_comm: Option<$NapiPolyComm>,
                #[napi(js_name = "range_check1_comm")]
                pub range_check1_comm: Option<$NapiPolyComm>,
                #[napi(js_name = "foreign_field_add_comm")]
                pub foreign_field_add_comm: Option<$NapiPolyComm>,
                #[napi(js_name = "foreign_field_mul_comm")]
                pub foreign_field_mul_comm: Option<$NapiPolyComm>,
                #[napi(js_name = "rot_comm")]
                pub rot_comm: Option<$NapiPolyComm>,
            }
            type NapiPlonkVerificationEvals = [<Napi $field_name:camel PlonkVerificationEvals>];

            impl From<&VerifierIndex<$G, OpeningProof<$G>>> for NapiPlonkVerificationEvals {
                fn from(index: &VerifierIndex<$G, OpeningProof<$G>>) -> Self {
                    Self {
                        sigma_comm: index.sigma_comm.iter().map(Into::into).collect(),
                        coefficients_comm: index.coefficients_comm.iter().map(Into::into).collect(),
                        generic_comm: index.generic_comm.clone().into(),
                        psm_comm: index.psm_comm.clone().into(),
                        complete_add_comm: index.complete_add_comm.clone().into(),
                        mul_comm: index.mul_comm.clone().into(),
                        emul_comm: index.emul_comm.clone().into(),
                        endomul_scalar_comm: index.endomul_scalar_comm.clone().into(),
                        xor_comm: index.xor_comm.clone().map(Into::into),
                        range_check0_comm: index.range_check0_comm.clone().map(Into::into),
                        range_check1_comm: index.range_check1_comm.clone().map(Into::into),
                        foreign_field_add_comm: index.foreign_field_add_comm.clone().map(Into::into),
                        foreign_field_mul_comm: index.foreign_field_mul_comm.clone().map(Into::into),
                        rot_comm: index.rot_comm.clone().map(Into::into),
                    }
                }
            }

            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            #[napi(object, js_name = [<Wasm $field_name:camel Shifts>])]
            pub struct [<Napi $field_name:camel Shifts>] {
                pub s0: $NapiF,
                pub s1: $NapiF,
                pub s2: $NapiF,
                pub s3: $NapiF,
                pub s4: $NapiF,
                pub s5: $NapiF,
                pub s6: $NapiF,
            }
            type NapiShifts = [<Napi $field_name:camel Shifts>];

            impl From<&[$F; 7]> for NapiShifts {
                fn from(shifts: &[$F; 7]) -> Self {
                    Self {
                        s0: shifts[0].into(),
                        s1: shifts[1].into(),
                        s2: shifts[2].into(),
                        s3: shifts[3].into(),
                        s4: shifts[4].into(),
                        s5: shifts[5].into(),
                        s6: shifts[6].into(),
                    }
                }
            }

            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            #[napi(object, js_name = [<Wasm $field_name:camel LookupSelectors>])]
            pub struct [<Napi $field_name:camel LookupSelectors>] {
                #[napi(js_name = "xor")]
                pub xor: Option<$NapiPolyComm>,
                #[napi(js_name = "lookup")]
                pub lookup: Option<$NapiPolyComm>,
                #[napi(js_name = "range_check")]
                pub range_check: Option<$NapiPolyComm>,
                #[napi(js_name = "ffmul")]
                pub ffmul: Option<$NapiPolyComm>,
            }
            type NapiLookupSelectors = [<Napi $field_name:camel LookupSelectors>];

            impl From<NapiLookupSelectors> for LookupSelectors<PolyComm<$G>> {
                fn from(x: NapiLookupSelectors) -> Self {
                    Self {
                        xor: x.xor.map(Into::into),
                        lookup: x.lookup.map(Into::into),
                        range_check: x.range_check.map(Into::into),
                        ffmul: x.ffmul.map(Into::into),
                    }
                }
            }

            impl From<&NapiLookupSelectors> for LookupSelectors<PolyComm<$G>> {
                fn from(x: &NapiLookupSelectors) -> Self {
                    Self {
                        xor: x.xor.clone().map(Into::into),
                        lookup: x.lookup.clone().map(Into::into),
                        range_check: x.range_check.clone().map(Into::into),
                        ffmul: x.ffmul.clone().map(Into::into),
                    }
                }
            }

            impl From<&LookupSelectors<PolyComm<$G>>> for NapiLookupSelectors {
                fn from(x: &LookupSelectors<PolyComm<$G>>) -> Self {
                    Self {
                        xor: x.xor.clone().map(Into::into),
                        lookup: x.lookup.clone().map(Into::into),
                        range_check: x.range_check.clone().map(Into::into),
                        ffmul: x.ffmul.clone().map(Into::into),
                    }
                }
            }

            impl From<LookupSelectors<PolyComm<$G>>> for NapiLookupSelectors {
                fn from(x: LookupSelectors<PolyComm<$G>>) -> Self {
                    Self {
                        xor: x.xor.clone().map(Into::into),
                        lookup: x.lookup.clone().map(Into::into),
                        range_check: x.range_check.clone().map(Into::into),
                        ffmul: x.ffmul.clone().map(Into::into),
                    }
                }
            }

            #[napi(object, js_name = [<Wasm $field_name:camel LookupVerifierIndex>])]
            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            pub struct [<Napi $field_name:camel LookupVerifierIndex>] {
                pub joint_lookup_used: bool,

                #[napi(js_name = "lookup_table")]
                pub lookup_table: NapiVector<$NapiPolyComm>,

                #[napi(js_name = "lookup_selectors")]
                pub lookup_selectors: NapiLookupSelectors,

                #[napi(js_name = "table_ids")]
                pub table_ids: Option<$NapiPolyComm>,

                #[napi(js_name = "lookup_info")]
                pub lookup_info: NapiLookupInfo,

                #[napi(js_name = "runtime_tables_selector")]
                pub runtime_tables_selector: Option<$NapiPolyComm>,
            }
            type NapiLookupVerifierIndex = [<Napi $field_name:camel LookupVerifierIndex>];

            impl From<&LookupVerifierIndex<$G>> for NapiLookupVerifierIndex {
                fn from(x: &LookupVerifierIndex<$G>) -> Self {
                    Self {
                        joint_lookup_used: x.joint_lookup_used.into(),
                        lookup_table: x.lookup_table.clone().iter().map(Into::into).collect(),
                        lookup_selectors: x.lookup_selectors.clone().into(),
                        table_ids: x.table_ids.clone().map(Into::into),
                        lookup_info: x.lookup_info.into(),
                        runtime_tables_selector: x.runtime_tables_selector.clone().map(Into::into)
                    }
                }
            }

            impl From<LookupVerifierIndex<$G>> for NapiLookupVerifierIndex {
                fn from(x: LookupVerifierIndex<$G>) -> Self {
                    Self {
                        joint_lookup_used: x.joint_lookup_used.into(),
                        lookup_table: x.lookup_table.iter().map(Into::into).collect(),
                        lookup_selectors: x.lookup_selectors.into(),
                        table_ids: x.table_ids.map(Into::into),
                        lookup_info: x.lookup_info.into(),
                        runtime_tables_selector: x.runtime_tables_selector.map(Into::into)
                    }
                }
            }

            impl From<&NapiLookupVerifierIndex> for LookupVerifierIndex<$G> {
                fn from(x: &NapiLookupVerifierIndex) -> Self {
                    Self {
                        joint_lookup_used: x.joint_lookup_used.into(),
                        lookup_table: x.lookup_table.clone().iter().map(Into::into).collect(),
                        lookup_selectors: x.lookup_selectors.clone().into(),
                        table_ids: x.table_ids.clone().map(Into::into),
                        lookup_info: x.lookup_info.clone().into(),
                        runtime_tables_selector: x.runtime_tables_selector.clone().map(Into::into)
                    }
                }
            }

            impl From<NapiLookupVerifierIndex> for LookupVerifierIndex<$G> {
                fn from(x: NapiLookupVerifierIndex) -> Self {
                    Self {
                        joint_lookup_used: x.joint_lookup_used.into(),
                        lookup_table: x.lookup_table.iter().map(Into::into).collect(),
                        lookup_selectors: x.lookup_selectors.into(),
                        table_ids: x.table_ids.map(Into::into),
                        lookup_info: x.lookup_info.into(),
                        runtime_tables_selector: x.runtime_tables_selector.map(Into::into)
                    }
                }
            }

            #[napi(object, js_name = [<Wasm $field_name:camel PlonkVerifierIndex>])]
            #[derive(Clone, Debug, Default)]
            pub struct [<Napi $field_name:camel PlonkVerifierIndex>] {
                pub domain: NapiDomain,
                #[napi(js_name = "max_poly_size")]
                pub max_poly_size: i32,
                #[napi(js_name = "public_")]
                pub public_: i32,
                #[napi(js_name = "prev_challenges")]
                pub prev_challenges: i32,
                pub srs: $NapiSrs,
                pub evals: NapiPlonkVerificationEvals,
                pub shifts: NapiShifts,
                #[napi(js_name = "lookup_index")]
                pub lookup_index: Option<NapiLookupVerifierIndex>,
                #[napi(js_name = "zk_rows")]
                pub zk_rows: i32,
            }
            type NapiPlonkVerifierIndex = [<Napi $field_name:camel PlonkVerifierIndex>];

            fn compute_feature_flags(index: &NapiPlonkVerifierIndex) -> FeatureFlags {
                let xor = index.evals.xor_comm.is_some();
                let range_check0 = index.evals.range_check0_comm.is_some();
                let range_check1 = index.evals.range_check1_comm.is_some();
                let foreign_field_add = index.evals.foreign_field_add_comm.is_some();
                let foreign_field_mul = index.evals.foreign_field_mul_comm.is_some();
                let rot = index.evals.rot_comm.is_some();

                let lookup = index
                    .lookup_index.as_ref()
                    .map_or(false, |li| li.lookup_info.features.patterns.lookup);

                let runtime_tables = index
                    .lookup_index.as_ref()
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

            impl From<NapiPlonkVerifierIndex> for VerifierIndex<$G, OpeningProof<$G>> {
                fn from(index: NapiPlonkVerifierIndex) -> Self {
                    let max_poly_size = index.max_poly_size;
                    let public_ = index.public_;
                    let prev_challenges = index.prev_challenges;
                    let log_size_of_group = index.domain.log_size_of_group;
                    let srs = &index.srs;
                    let evals = &index.evals;
                    let shifts = &index.shifts;

                    let (endo_q, _endo_r) = poly_commitment::ipa::endos::<GAffineOther>();
                    let domain = Domain::<$F>::new(1 << log_size_of_group).unwrap();

                    let feature_flags = compute_feature_flags(&index);
                    let (linearization, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);

                    let index = {
                        let zk_rows = index.zk_rows as u64;

                        VerifierIndex {
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

            impl From<&VerifierIndex<$G, OpeningProof<$G>>> for NapiPlonkVerifierIndex {
                fn from(index: &VerifierIndex<$G, OpeningProof<$G>>) -> Self {
                    Self {
                        domain: (&index.domain).into(),
                        max_poly_size: index.max_poly_size as i32,
                        public_: index.public as i32,
                        prev_challenges: index.prev_challenges as i32,
                        srs: (&index.srs).into(),
                        evals: index.into(),
                        shifts: (&index.shift).into(),
                        lookup_index: index.lookup_index.as_ref().map(Into::into),
                        zk_rows: index.zk_rows as i32,
                    }
                }
            }

            pub fn read_raw(
                offset: Option<i32>,
                srs: &$NapiSrs,
                path: String,
            ) -> napi::Result<VerifierIndex<$G, OpeningProof<$G>>> {
                let path = Path::new(&path);
                let (endo_q, _endo_r) = poly_commitment::ipa::endos::<$GOther>();
                VerifierIndex::<$G, OpeningProof<$G>>::from_file(
                    srs.0.clone(),
                    path,
                    offset.map(|x| x as u64),
                    endo_q,
                ).map_err(|e| Error::new(Status::GenericFailure, format!("read_raw: {}", e)))
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_read>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_read>](
                offset: Option<i32>,
                srs: &$NapiSrs,
                path: String,
            ) -> napi::Result<NapiPlonkVerifierIndex> {
                let vi = read_raw(offset, srs, path)?;
                Ok(NapiPlonkVerifierIndex::from(&vi))
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_write>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_write>](
                append: Option<bool>,
                index: NapiPlonkVerifierIndex,
                path: String,
            ) -> napi::Result<()> {
                let index: VerifierIndex<$G, OpeningProof<$G>> = index.into();
                let path = Path::new(&path);
                index
                    .to_file(path, append)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("plonk_verifier_index_write: {}", e)))
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_serialize>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_serialize>](
                index: NapiPlonkVerifierIndex,
            ) -> String {
                let index: VerifierIndex<$G, OpeningProof<$G>> = index.into();
                serde_json::to_string(&index).unwrap()
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_deserialize>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_deserialize>](
                _srs: &$NapiSrs,
                index: String,
            ) -> napi::Result<NapiPlonkVerifierIndex> {
                match serde_json::from_str::<VerifierIndex<$G, OpeningProof<$G>>>(&index) {
                    Ok(vi) => Ok(NapiPlonkVerifierIndex::from(&vi)),
                    Err(e) => Err(Error::new(Status::GenericFailure, e.to_string())),
                }
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_create>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_create>](
                index: &External<$NapiIndex>,
            ) -> NapiPlonkVerifierIndex {
                index.0.srs.get_lagrange_basis(index.0.as_ref().cs.domain.d1);
                let verifier_index = index.0.as_ref().verifier_index();
                // `VerifierIndex::verifier_index()` may not carry the full SRS `g` points
                // (it can be trimmed for verifier-only usage). We need the full SRS here
                // because OCaml calls `SRS.lagrange_commitments_whole_domain vk.srs ...`,
                // which computes Lagrange commitments from `srs.g`.
                let mut napi_index = NapiPlonkVerifierIndex::from(&verifier_index);
                napi_index.srs = (&index.0.srs).into();
                napi_index
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_shifts>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_shifts>](log2_size: i32) -> napi::bindgen_prelude::Result<NapiShifts> {
                println!(
                    "from napi! caml_pasta_plonk_verifier_index_shifts with log2_size {}",
                    log2_size
                );

                let size = 1usize << (log2_size as u32);
                let domain = Domain::<$F>::new(size)
                    .ok_or_else(|| Error::new(Status::InvalidArg, "failed to create evaluation domain"))?;

                let shifts = Shifts::new(&domain);
                let s = shifts.shifts();

                Ok(NapiShifts {
                    s0: s[0].clone().into(),
                    s1: s[1].clone().into(),
                    s2: s[2].clone().into(),
                    s3: s[3].clone().into(),
                    s4: s[4].clone().into(),
                    s5: s[5].clone().into(),
                    s6: s[6].clone().into(),
                })
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_dummy>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_dummy>]() -> NapiPlonkVerifierIndex {
                fn comm() -> $NapiPolyComm {
                    let g: $NapiG = $G::generator().into();
                    $NapiPolyComm {
                        shifted: None,
                        unshifted: vec![g].into(),
                    }
                }
                fn vec_comm(num: usize) -> NapiVector<$NapiPolyComm> {
                    (0..num).map(|_| comm()).collect()
                }

                NapiPlonkVerifierIndex {
                    domain: NapiDomain {
                        log_size_of_group: 1,
                        group_gen: $F::one().into(),
                    },
                    max_poly_size: 0,
                    public_: 0,
                    prev_challenges: 0,
                    srs: $NapiSrs(Arc::new(SRS::create(0))),
                    evals: NapiPlonkVerificationEvals {
                        sigma_comm: vec_comm(PERMUTS),
                        coefficients_comm: vec_comm(COLUMNS),
                        generic_comm: comm(),
                        psm_comm: comm(),
                        complete_add_comm: comm(),
                        mul_comm: comm(),
                        emul_comm: comm(),
                        endomul_scalar_comm: comm(),
                        xor_comm: None,
                        range_check0_comm: None,
                        range_check1_comm: None,
                        foreign_field_add_comm: None,
                        foreign_field_mul_comm: None,
                        rot_comm: None,
                    },
                    shifts:
                        NapiShifts {
                            s0: $F::one().into(),
                            s1: $F::one().into(),
                            s2: $F::one().into(),
                            s3: $F::one().into(),
                            s4: $F::one().into(),
                            s5: $F::one().into(),
                            s6: $F::one().into(),
                        },
                    lookup_index: None,
                    zk_rows: 3,
                }
            }

            #[napi(js_name = [<caml_pasta_ $field_name:snake _plonk_verifier_index_deep_copy>])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_verifier_index_deep_copy>](
                x: NapiPlonkVerifierIndex,
            ) -> NapiPlonkVerifierIndex {
                x.clone()
            }

        }
    }
}

pub mod fp {
    use super::*;
    use crate::{
        pasta_fp_plonk_index::WasmPastaFpPlonkIndex as NapiPastaFpPlonkIndex,
        poly_comm::vesta::NapiFpPolyComm as NapiPolyComm,
        srs::fp::NapiFpSrs,
        wrappers::{field::NapiPastaFp, group::NapiGVesta},
    };
    use mina_curves::pasta::{Fp, Pallas as GAffineOther, Vesta as GAffine};

    impl_verification_key!(
        NapiGVesta,
        GAffine,
        NapiPastaFp,
        Fp,
        NapiPolyComm,
        NapiFpSrs,
        GAffineOther,
        mina_poseidon::pasta::fp_kimchi,
        mina_poseidon::pasta::fq_kimchi,
        NapiPastaFpPlonkIndex,
        fp
    );
}

pub mod fq {
    use super::*;
    use crate::{
        pasta_fq_plonk_index::WasmPastaFqPlonkIndex as NapiPastaFqPlonkIndex,
        poly_comm::pallas::NapiFqPolyComm as NapiPolyComm,
        srs::fq::NapiFqSrs,
        wrappers::{field::NapiPastaFq, group::NapiGPallas},
    };
    use mina_curves::pasta::{Fq, Pallas as GAffine, Vesta as GAffineOther};

    impl_verification_key!(
        NapiGPallas,
        GAffine,
        NapiPastaFq,
        Fq,
        NapiPolyComm,
        NapiFqSrs,
        GAffineOther,
        mina_poseidon::pasta::fq_kimchi,
        mina_poseidon::pasta::fp_kimchi,
        NapiPastaFqPlonkIndex,
        fq
    );
}
