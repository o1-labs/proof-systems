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
    verifier_index::{LookupVerifierIndex, VerifierIndex as DlogVerifierIndex},
};
use napi::{bindgen_prelude::*, Error as NapiError, Status};
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
     $name: ident,
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
            #[derive(Clone, Copy)]
            pub struct [<Napi $field_name:camel Domain>] {
                #[napi(js_name = "log_size_of_group")]
                pub log_size_of_group: i32,
                #[napi(js_name = "group_gen")]
                pub group_gen: $NapiF,
            }
            type NapiDomain = [<Napi $field_name:camel Domain>];

            // #[napi]
            // impl [<Napi $field_name:camel Domain>] {
            //     #[napi(constructor)]
            //     pub fn new(log_size_of_group: i32, group_gen: $NapiF) -> Self {
            //         NapiDomain {log_size_of_group, group_gen}
            //     }
            // }

            impl From<NapiDomain> for Domain<$F> {
                fn from(domain: NapiDomain) -> Self {
                    let size = 1 << domain.log_size_of_group;
                    Domain::<$F>::new(size).expect("Failed to create evaluation domain")
                }
            }

            // impl FromNapiValue for [<Napi $field_name:camel Domain>] {
            //     unsafe fn from_napi_value(
            //         env: sys::napi_env,
            //         napi_val: sys::napi_value,
            //     ) -> Result<Self> {
            //         let instance = <ClassInstance<[<Napi $field_name:camel Domain>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
            //         Ok((*instance).clone())
            //     }
            // }

            // impl<'a> ToNapiValue for &'a mut [<Napi $field_name:camel Domain>] {
            //     unsafe fn to_napi_value(
            //         env: sys::napi_env,
            //         val: Self,
            //     ) -> Result<sys::napi_value> {
            //         <[<Napi $field_name:camel Domain>] as ToNapiValue>::to_napi_value(env, val.clone())
            //     }
            // }

            #[napi(object, js_name = [<Wasm $field_name:camel PlonkVerificationEvals>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel PlonkVerificationEvals>] {
                #[napi(skip, js_name = "sigma_comm")]
                pub sigma_comm: NapiVector<$NapiPolyComm>,
                #[napi(skip, js_name = "coefficients_comm")]
                pub coefficients_comm: NapiVector<$NapiPolyComm>,
                #[napi(skip, js_name = "generic_comm")]
                pub generic_comm: $NapiPolyComm,
                #[napi(skip, js_name = "psm_comm")]
                pub psm_comm: $NapiPolyComm,
                #[napi(skip, js_name = "complete_add_comm")]
                pub complete_add_comm: $NapiPolyComm,
                #[napi(skip, js_name = "mul_comm")]
                pub mul_comm: $NapiPolyComm,
                #[napi(skip, js_name = "emul_comm")]
                pub emul_comm: $NapiPolyComm,
                #[napi(skip, js_name = "endomul_scalar_comm")]
                pub endomul_scalar_comm: $NapiPolyComm,
                #[napi(skip, js_name = "xor_comm")]
                pub xor_comm: Option<$NapiPolyComm>,
                #[napi(skip, js_name = "range_check0_comm")]
                pub range_check0_comm: Option<$NapiPolyComm>,
                #[napi(skip, js_name = "range_check1_comm")]
                pub range_check1_comm: Option<$NapiPolyComm>,
                #[napi(skip, js_name = "foreign_field_add_comm")]
                pub foreign_field_add_comm: Option<$NapiPolyComm>,
                #[napi(skip, js_name = "foreign_field_mul_comm")]
                pub foreign_field_mul_comm: Option<$NapiPolyComm>,
                #[napi(skip, js_name = "rot_comm")]
                pub rot_comm: Option<$NapiPolyComm>
            }

            type NapiPlonkVerificationEvals = [<Napi $field_name:camel PlonkVerificationEvals>];

            // impl FromNapiValue for [<Napi $field_name:camel PlonkVerificationEvals>] {
            //     unsafe fn from_napi_value(
            //         env: sys::napi_env,
            //         napi_val: sys::napi_value,
            //     ) -> Result<Self> {
            //         let instance = <ClassInstance<[<Napi $field_name:camel PlonkVerificationEvals>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
            //         Ok((*instance).clone())
            //     }
            // }

            // #[napi]
            // impl [<Napi $field_name:camel PlonkVerificationEvals>] {
            //     #[allow(clippy::too_many_arguments)]
            //     #[napi(constructor)]
            //     pub fn new(
            //         sigma_comm: NapiVector<$NapiPolyComm>,
            //         coefficients_comm: NapiVector<$NapiPolyComm>,
            //         generic_comm: &$NapiPolyComm,
            //         psm_comm: &$NapiPolyComm,
            //         complete_add_comm: &$NapiPolyComm,
            //         mul_comm: &$NapiPolyComm,
            //         emul_comm: &$NapiPolyComm,
            //         endomul_scalar_comm: &$NapiPolyComm,
            //         xor_comm: Option<$NapiPolyComm>,
            //         range_check0_comm: Option<$NapiPolyComm>,
            //         range_check1_comm: Option<$NapiPolyComm>,
            //         foreign_field_add_comm: Option<$NapiPolyComm>,
            //         foreign_field_mul_comm: Option<$NapiPolyComm>,
            //         rot_comm: Option<$NapiPolyComm>,
            //         ) -> Self {
            //         NapiPlonkVerificationEvals {
            //             sigma_comm: sigma_comm.clone(),
            //             coefficients_comm: coefficients_comm.clone(),
            //             generic_comm: generic_comm.clone(),
            //             psm_comm: psm_comm.clone(),
            //             complete_add_comm: complete_add_comm.clone(),
            //             mul_comm: mul_comm.clone(),
            //             emul_comm: emul_comm.clone(),
            //             endomul_scalar_comm: endomul_scalar_comm.clone(),
            //             xor_comm: xor_comm.clone(),
            //             range_check0_comm: range_check0_comm.clone(),
            //             range_check1_comm: range_check1_comm.clone(),
            //             foreign_field_mul_comm: foreign_field_mul_comm.clone(),
            //             foreign_field_add_comm: foreign_field_add_comm.clone(),
            //             rot_comm: rot_comm.clone(),
            //         }
            //     }

            //     #[napi(getter, js_name = "sigma_comm")]
            //     pub fn sigma_comm(&self) -> NapiVector<$NapiPolyComm> {
            //         self.sigma_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_sigma_comm")]
            //     pub fn set_sigma_comm(&mut self, x: NapiVector<$NapiPolyComm>) {
            //         self.sigma_comm = x;
            //     }

            //     #[napi(getter, js_name = "coefficients_comm")]
            //     pub fn coefficients_comm(&self) -> NapiVector<$NapiPolyComm> {
            //         self.coefficients_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_coefficients_comm")]
            //     pub fn set_coefficients_comm(&mut self, x: NapiVector<$NapiPolyComm>) {
            //         self.coefficients_comm = x;
            //     }

            //     #[napi(getter, js_name = "generic_comm")]
            //     pub fn generic_comm(&self) -> $NapiPolyComm {
            //         self.generic_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_generic_comm")]
            //     pub fn set_generic_comm(&mut self, x: $NapiPolyComm) {
            //         self.generic_comm = x;
            //     }

            //     #[napi(getter, js_name = "psm_comm")]
            //     pub fn psm_comm(&self) -> $NapiPolyComm {
            //         self.psm_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_psm_comm")]
            //     pub fn set_psm_comm(&mut self, x: $NapiPolyComm) {
            //         self.psm_comm = x;
            //     }

            //     #[napi(getter, js_name = "complete_add_comm")]
            //     pub fn complete_add_comm(&self) -> $NapiPolyComm {
            //         self.complete_add_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_complete_add_comm")]
            //     pub fn set_complete_add_comm(&mut self, x: $NapiPolyComm) {
            //         self.complete_add_comm = x;
            //     }

            //     #[napi(getter, js_name = "mul_comm")]
            //     pub fn mul_comm(&self) -> $NapiPolyComm {
            //         self.mul_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_mul_comm")]
            //     pub fn set_mul_comm(&mut self, x: $NapiPolyComm) {
            //         self.mul_comm = x;
            //     }

            //     #[napi(getter, js_name = "emul_comm")]
            //     pub fn emul_comm(&self) -> $NapiPolyComm {
            //         self.emul_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_emul_comm")]
            //     pub fn set_emul_comm(&mut self, x: $NapiPolyComm) {
            //         self.emul_comm = x;
            //     }

            //     #[napi(getter, js_name = "endomul_scalar_comm")]
            //     pub fn endomul_scalar_comm(&self) -> $NapiPolyComm {
            //         self.endomul_scalar_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_endomul_scalar_comm")]
            //     pub fn set_endomul_scalar_comm(&mut self, x: $NapiPolyComm) {
            //         self.endomul_scalar_comm = x;
            //     }

            //     #[napi(getter, js_name = "xor_comm")]
            //     pub fn xor_comm(&self) -> Option<$NapiPolyComm> {
            //         self.xor_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_xor_comm")]
            //     pub fn set_xor_comm(&mut self, x: Option<$NapiPolyComm>) {
            //         self.xor_comm = x;
            //     }

            //     #[napi(getter, js_name = "rot_comm")]
            //     pub fn rot_comm(&self) -> Option<$NapiPolyComm> {
            //         self.rot_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_rot_comm")]
            //     pub fn set_rot_comm(&mut self, x: Option<$NapiPolyComm>) {
            //         self.rot_comm = x;
            //     }

            //     #[napi(getter, js_name = "range_check0_comm")]
            //     pub fn range_check0_comm(&self) -> Option<$NapiPolyComm> {
            //         self.range_check0_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_range_check0_comm")]
            //     pub fn set_range_check0_comm(&mut self, x: Option<$NapiPolyComm>) {
            //         self.range_check0_comm = x;
            //     }

            //     #[napi(getter, js_name = "range_check1_comm")]
            //     pub fn range_check1_comm(&self) -> Option<$NapiPolyComm> {
            //         self.range_check1_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_range_check1_comm")]
            //     pub fn set_range_check1_comm(&mut self, x: Option<$NapiPolyComm>) {
            //         self.range_check1_comm = x;
            //     }

            //     #[napi(getter, js_name = "foreign_field_add_comm")]
            //     pub fn foreign_field_add_comm(&self) -> Option<$NapiPolyComm> {
            //         self.foreign_field_add_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_foreign_field_add_comm")]
            //     pub fn set_foreign_field_add_comm(&mut self, x: Option<$NapiPolyComm>) {
            //         self.foreign_field_add_comm = x;
            //     }

            //     #[napi(getter, js_name = "foreign_field_mul_comm")]
            //     pub fn foreign_field_mul_comm(&self) -> Option<$NapiPolyComm> {
            //         self.foreign_field_mul_comm.clone()
            //     }

            //     #[napi(setter, js_name = "set_foreign_field_mul_comm")]
            //     pub fn set_foreign_field_mul_comm(&mut self, x: Option<$NapiPolyComm>) {
            //         self.foreign_field_mul_comm = x;
            //     }

            // }

            #[derive(Clone, Copy)]
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

            // impl FromNapiValue for [<Napi $field_name:camel Shifts>] {
            //     unsafe fn from_napi_value(
            //         env: sys::napi_env,
            //         napi_val: sys::napi_value,
            //     ) -> Result<Self> {
            //         let instance = <ClassInstance<[<Napi $field_name:camel Shifts>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
            //         Ok((*instance).clone())
            //     }
            // }

            // impl<'a> ToNapiValue for &'a mut [<Napi $field_name:camel Shifts>] {
            //     unsafe fn to_napi_value(
            //         env: sys::napi_env,
            //         val: Self,
            //     ) -> Result<sys::napi_value> {
            //         <[<Napi $field_name:camel Shifts>] as ToNapiValue>::to_napi_value(env, val.clone())
            //     }
            // }

            // #[napi]
            // impl [<Napi $field_name:camel Shifts>] {
            //     #[napi(constructor)]
            //     pub fn new(
            //         s0: $NapiF,
            //         s1: $NapiF,
            //         s2: $NapiF,
            //         s3: $NapiF,
            //         s4: $NapiF,
            //         s5: $NapiF,
            //         s6: $NapiF
            //     ) -> Self {
            //         Self { s0, s1, s2, s3, s4, s5, s6 }
            //     }
            // }

            #[napi(js_name = [<Wasm $field_name:camel LookupSelectors>])]
            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            pub struct [<Napi $field_name:camel LookupSelectors>] {
                #[napi(skip)]
                pub xor: Option<$NapiPolyComm>,
                #[napi(skip)]
                pub lookup : Option<$NapiPolyComm>,
                #[napi(skip)]
                pub range_check: Option<$NapiPolyComm>,
                #[napi(skip)]
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

            impl FromNapiValue for [<Napi $field_name:camel LookupSelectors>] {
                unsafe fn from_napi_value(
                    env: sys::napi_env,
                    napi_val: sys::napi_value,
                ) -> Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel LookupSelectors>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

            #[napi]
            impl [<Napi $field_name:camel LookupSelectors>] {
                #[napi(constructor)]
                pub fn new(
                    xor: Option<$NapiPolyComm>,
                    lookup: Option<$NapiPolyComm>,
                    range_check: Option<$NapiPolyComm>,
                    ffmul: Option<$NapiPolyComm>
                ) -> Self {
                    Self {
                        xor,
                        lookup,
                        range_check,
                        ffmul
                    }
                }

                #[napi(getter)]
                pub fn xor(&self) -> Option<$NapiPolyComm> {
                    self.xor.clone()
                }

                #[napi(setter, js_name = "set_xor")]
                pub fn set_xor(&mut self, x: Option<$NapiPolyComm>) {
                    self.xor = x
                }

                #[napi(getter)]
                pub fn lookup(&self) -> Option<$NapiPolyComm> {
                    self.lookup.clone()
                }

                #[napi(setter, js_name = "set_lookup")]
                pub fn set_lookup(&mut self, x: Option<$NapiPolyComm>) {
                    self.lookup = x
                }

                #[napi(getter)]
                pub fn ffmul(&self) -> Option<$NapiPolyComm> {
                    self.ffmul.clone()
                }

                #[napi(setter, js_name = "set_ffmul")]
                pub fn set_ffmul(&mut self, x: Option<$NapiPolyComm>) {
                    self.ffmul = x
                }

                #[napi(getter, js_name = "range_check")]
                pub fn range_check(&self) -> Option<$NapiPolyComm> {
                    self.range_check.clone()
                }

                #[napi(setter, js_name = "set_range_check")]
                pub fn set_range_check(&mut self, x: Option<$NapiPolyComm>) {
                    self.range_check = x
                }
            }

            #[napi(object, js_name = [<Wasm $field_name:camel LookupVerifierIndex>])]
            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            pub struct [<Napi $field_name:camel LookupVerifierIndex>] {
                #[napi(js_name = "joint_lookup_used")]
                pub joint_lookup_used: bool,

                #[napi(skip)]
                pub lookup_table: NapiVector<$NapiPolyComm>,

                #[napi(skip, js_name = "lookup_selectors")]
                pub lookup_selectors: NapiLookupSelectors,

                #[napi(skip)]
                pub table_ids: Option<$NapiPolyComm>,

                #[napi(skip)]
                pub lookup_info: NapiLookupInfo,

                #[napi(skip)]
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

            // impl FromNapiValue for [<Napi $field_name:camel LookupVerifierIndex>] {
            //     unsafe fn from_napi_value(
            //         env: sys::napi_env,
            //         napi_val: sys::napi_value,
            //     ) -> Result<Self> {
            //         let instance = <ClassInstance<[<Napi $field_name:camel LookupVerifierIndex>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
            //         Ok((*instance).clone())
            //     }
            // }

            // #[napi]
            // impl [<Napi $field_name:camel LookupVerifierIndex>] {
            //     #[napi(constructor)]
            //     pub fn new(
            //         joint_lookup_used: bool,
            //         lookup_table: NapiVector<$NapiPolyComm>,
            //         lookup_selectors: NapiLookupSelectors,
            //         table_ids: Option<$NapiPolyComm>,
            //         lookup_info: NapiLookupInfo,
            //         runtime_tables_selector: Option<$NapiPolyComm>
            //     ) -> NapiLookupVerifierIndex {
            //         NapiLookupVerifierIndex {
            //             joint_lookup_used,
            //             lookup_table,
            //             lookup_selectors,
            //             table_ids,
            //             lookup_info: lookup_info.clone(),
            //             runtime_tables_selector
            //         }
            //     }

            //     #[napi(getter, js_name = "lookup_table")]
            //     pub fn lookup_table(&self) -> NapiVector<$NapiPolyComm> {
            //         self.lookup_table.clone()
            //     }

            //     #[napi(setter, js_name = "set_lookup_table")]
            //     pub fn set_lookup_table(&mut self, x: NapiVector<$NapiPolyComm>) {
            //         self.lookup_table = x
            //     }

            //     #[napi(getter, js_name = "lookup_selectors")]
            //     pub fn lookup_selectors(&self) -> NapiLookupSelectors {
            //         self.lookup_selectors.clone()
            //     }

            //     #[napi(setter, js_name = "set_lookup_selectors")]
            //     pub fn set_lookup_selectors(&mut self, x: NapiLookupSelectors) {
            //         self.lookup_selectors = x
            //     }

            //     #[napi(getter, js_name = "table_ids")]
            //     pub fn table_ids(&self) -> Option<$NapiPolyComm>{
            //         self.table_ids.clone()
            //     }

            //     #[napi(setter, js_name = "set_table_ids")]
            //     pub fn set_table_ids(&mut self, x: Option<$NapiPolyComm>) {
            //         self.table_ids = x
            //     }

            //     #[napi(getter, js_name = "lookup_info")]
            //     pub fn lookup_info(&self) -> NapiLookupInfo {
            //         self.lookup_info.clone()
            //     }

            //     #[napi(setter, js_name = "set_lookup_info")]
            //     pub fn set_lookup_info(&mut self, x: NapiLookupInfo) {
            //         self.lookup_info = x
            //     }

            //     #[napi(getter, js_name = "runtime_tables_selector")]
            //     pub fn runtime_tables_selector(&self) -> Option<$NapiPolyComm> {
            //         self.runtime_tables_selector.clone()
            //     }

            //     #[napi(setter, js_name = "set_runtime_tables_selector")]
            //     pub fn set_runtime_tables_selector(&mut self, x: Option<$NapiPolyComm>) {
            //         self.runtime_tables_selector = x
            //     }
            // }

            #[napi(object, js_name = [<Wasm $field_name:camel PlonkVerifierIndex>])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel PlonkVerifierIndex>] {
                pub domain: NapiDomain,
                #[napi(js_name = "max_poly_size")]
                pub max_poly_size: i32,
                pub public_: i32,
                pub prev_challenges: i32,
                #[napi(skip)]
                pub srs: $NapiSrs,
                #[napi(skip)]
                pub evals: NapiPlonkVerificationEvals,
                pub shifts: NapiShifts,
                #[napi(js_name = "lookup_index")]
                pub lookup_index: Option<NapiLookupVerifierIndex>,
                pub zk_rows: i32,
            }

            type NapiPlonkVerifierIndex = [<Napi $field_name:camel PlonkVerifierIndex>];

            // impl FromNapiValue for [<Napi $field_name:camel PlonkVerifierIndex>] {
            //     unsafe fn from_napi_value(
            //         env: sys::napi_env,
            //         napi_val: sys::napi_value,
            //     ) -> Result<Self> {
            //         let instance = <ClassInstance<[<Napi $field_name:camel PlonkVerifierIndex>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
            //         Ok((*instance).clone())
            //     }
            // }

            // #[napi]
            // impl [<Napi $field_name:camel PlonkVerifierIndex>] {
            //     #[napi(constructor)]
            //     #[allow(clippy::too_many_arguments)]
            //     pub fn new(
            //         domain: &NapiDomain,
            //         max_poly_size: i32,
            //         public_: i32,
            //         prev_challenges: i32,
            //         srs: &$NapiSrs,
            //         evals: &NapiPlonkVerificationEvals,
            //         shifts: &NapiShifts,
            //         lookup_index: Option<NapiLookupVerifierIndex>,
            //         zk_rows: i32,
            //     ) -> Self {
            //         NapiPlonkVerifierIndex {
            //             domain: domain.clone(),
            //             max_poly_size,
            //             public_,
            //             prev_challenges,
            //             srs: srs.clone(),
            //             evals: evals.clone(),
            //             shifts: shifts.clone(),
            //             lookup_index: lookup_index.clone(),
            //             zk_rows,
            //         }
            //     }

            //     #[napi(getter)]
            //     pub fn srs(&self) -> $NapiSrs {
            //         self.srs.clone()
            //     }

            //     #[napi(setter, js_name = "set_srs")]
            //     pub fn set_srs(&mut self, x: $NapiSrs) {
            //         self.srs = x
            //     }

            //     #[napi(getter)]
            //     pub fn evals(&self) -> NapiPlonkVerificationEvals {
            //         self.evals.clone()
            //     }

            //     #[napi(setter, js_name = "set_evals")]
            //     pub fn set_evals(&mut self, x: NapiPlonkVerificationEvals) {
            //         self.evals = x
            //     }

            //     #[napi(getter, js_name = "lookup_index")]
            //     pub fn lookup_index(&self) -> Option<NapiLookupVerifierIndex> {
            //         self.lookup_index.clone()
            //     }

            //     #[napi(setter, js_name = "set_lookup_index")]
            //     pub fn set_lookup_index(&mut self, li: Option<NapiLookupVerifierIndex>) {
            //         self.lookup_index = li
            //     }
            // }

            pub fn to_napi(
                srs: &Arc<SRS<$G>>,
                vi: DlogVerifierIndex<$G, OpeningProof<$G>>,
            ) -> NapiPlonkVerifierIndex {
                NapiPlonkVerifierIndex {
                    domain: NapiDomain {
                        log_size_of_group: vi.domain.log_size_of_group as i32,
                        group_gen: vi.domain.group_gen.into(),
                    },
                    max_poly_size: vi.max_poly_size as i32,
                    public_: vi.public as i32,
                    prev_challenges: vi.prev_challenges as i32,
                    srs: srs.into(),
                    evals: NapiPlonkVerificationEvals {
                        sigma_comm: IntoIterator::into_iter(vi.sigma_comm).map(From::from).collect(),
                        coefficients_comm: IntoIterator::into_iter(vi.coefficients_comm).map(From::from).collect(),
                        generic_comm: vi.generic_comm.into(),
                        psm_comm: vi.psm_comm.into(),
                        complete_add_comm: vi.complete_add_comm.into(),
                        mul_comm: vi.mul_comm.into(),
                        emul_comm: vi.emul_comm.into(),
                        endomul_scalar_comm: vi.endomul_scalar_comm.into(),
                        xor_comm: vi.xor_comm.map(|v| v.into()),
                        range_check0_comm: vi.range_check0_comm.map(|v| v.into()),
                        range_check1_comm: vi.range_check1_comm.map(|v| v.into()),
                        foreign_field_add_comm: vi.foreign_field_add_comm.map(|v| v.into()),
                        foreign_field_mul_comm: vi.foreign_field_mul_comm.map(|v| v.into()),
                        rot_comm: vi.rot_comm.map(|v| v.into())
                    },
                    shifts:
                        NapiShifts {
                            s0: vi.shift[0].into(),
                            s1: vi.shift[1].into(),
                            s2: vi.shift[2].into(),
                            s3: vi.shift[3].into(),
                            s4: vi.shift[4].into(),
                            s5: vi.shift[5].into(),
                            s6: vi.shift[6].into(),
                        },
                    lookup_index: vi.lookup_index.map(Into::into),
                    zk_rows: vi.zk_rows as i32,
                }
            }

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

            pub fn of_napi(
                index: NapiPlonkVerifierIndex,
            ) -> (DlogVerifierIndex<GAffine, OpeningProof<GAffine>>, Arc<SRS<GAffine>>) {
                let max_poly_size = index.max_poly_size;
                let public_ = index.public_;
                let prev_challenges = index.prev_challenges;
                let log_size_of_group = index.domain.log_size_of_group;
                let srs = &index.srs;
                let evals = &index.evals;
                let shifts = &index.shifts;

                let (endo_q, _endo_r) = poly_commitment::ipa::endos::<$GOther>();
                let domain = Domain::<$F>::new(1 << log_size_of_group).unwrap();

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
                            res.set(permutation_vanishing_polynomial(domain, zk_rows)).unwrap();
                            res
                        },
                        shift: [
                            shifts.s0.into(),
                            shifts.s1.into(),
                            shifts.s2.into(),
                            shifts.s3.into(),
                            shifts.s4.into(),
                            shifts.s5.into(),
                            shifts.s6.into()
                        ],
                        srs: {
                          Arc::clone(&srs.0)
                        },

                        zk_rows,

                        linearization,
                        powers_of_alpha,
                        lookup_index: index.lookup_index.map(Into::into),
                    }
                };
                (index, srs.0.clone())
            }

            impl From<NapiPlonkVerifierIndex> for DlogVerifierIndex<$G, OpeningProof<$G>> {
                fn from(index: NapiPlonkVerifierIndex) -> Self {
                    of_napi(index).0
                }
            }

            pub fn read_raw(
                offset: Option<i32>,
                srs: &$NapiSrs,
                path: String,
            ) -> Result<DlogVerifierIndex<$G, OpeningProof<$G>>> {
                let path = Path::new(&path);
                let (endo_q, _endo_r) = poly_commitment::ipa::endos::<GAffineOther>();
                DlogVerifierIndex::<$G, OpeningProof<$G>>::from_file(
                    srs.0.clone(),
                    path,
                    offset.map(|x| x as u64),
                    endo_q,
                ).map_err(|e| NapiError::new(Status::GenericFailure, format!("read_raw: {}", e).as_str()))
            }

            #[napi(js_name = [<$name:snake _read>])]
            pub fn [<$name:snake _read>](
                offset: Option<i32>,
                srs: &$NapiSrs,
                path: String,
            ) -> Result<NapiPlonkVerifierIndex> {
                let vi = read_raw(offset, srs, path)?;
                Ok(to_napi(srs, vi.into()))
            }

            #[napi(js_name = [<$name:snake _write>])]
            pub fn [<$name:snake _write>](
                append: Option<bool>,
                index: NapiPlonkVerifierIndex,
                path: String,
            ) -> Result<()> {
                let index: DlogVerifierIndex<$G, OpeningProof<$G>> = index.into();
                let path = Path::new(&path);
                index.to_file(path, append).map_err(|e| {
                    println!("{}", e);
                    NapiError::new(Status::GenericFailure, "caml_pasta_fp_plonk_verifier_index_raw_read")
                })
            }

            #[napi(js_name = [<$name:snake _serialize>])]
            pub fn [<$name:snake _serialize>](
                index: NapiPlonkVerifierIndex,
            ) -> String {
                let index: DlogVerifierIndex<$G, OpeningProof<$G>> = index.into();
                serde_json::to_string(&index).unwrap()
            }

            #[napi(js_name = [<$name:snake _deserialize>])]
            pub fn [<$name:snake _deserialize>](
                srs: &$NapiSrs,
                index: String,
            ) -> napi::Result<NapiPlonkVerifierIndex> {
                let vi = serde_json::from_str::<DlogVerifierIndex<$G, OpeningProof<$G>>>(&index);
                match vi {
                    Ok(vi) => Ok(to_napi(srs, vi)),
                    Err(e) => Err(NapiError::new(Status::GenericFailure, format!("deserialize: {}", e))),
                }
            }

            #[napi(js_name = [<$name:snake _create>])]
            pub fn [<$name:snake _create>](
                index: &External<$NapiIndex>,
            ) -> NapiPlonkVerifierIndex {
                index.0.srs.get_lagrange_basis(index.0.as_ref().cs.domain.d1);
                let verifier_index = index.0.verifier_index();
                to_napi(&index.0.as_ref().srs, verifier_index)
            }

            #[napi(js_name = [<$name:snake _shifts>])]
            pub fn [<$name:snake _shifts>](
                log2_size: i32,
            ) -> napi::bindgen_prelude::Result<NapiShifts> {
                println!(
                    "from napi! caml_pasta_fp_plonk_verifier_index_shifts with log2_size {}",
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
            // pub fn [<$name:snake _shifts>](log2_size: i32) -> NapiShifts {
            //     let domain = Domain::<$F>::new(1 << log2_size).unwrap();
            //     let shifts = Shifts::new(&domain);
            //     let s = shifts.shifts();
            //     NapiShifts {
            //         s0: s[0].clone().into(),
            //         s1: s[1].clone().into(),
            //         s2: s[2].clone().into(),
            //         s3: s[3].clone().into(),
            //         s4: s[4].clone().into(),
            //         s5: s[5].clone().into(),
            //         s6: s[6].clone().into(),
            //     }
            // }

            #[napi(js_name = [<$name:snake _dummy>])]
            pub fn [<$name:snake _dummy>]() -> NapiPlonkVerifierIndex {
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

            #[napi(js_name = [<$name:snake _deep_copy>])]
            pub fn [<$name:snake _deep_copy>](
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
        pasta_fp_plonk_index::WasmPastaFpPlonkIndex,
        poly_comm::vesta::NapiFpPolyComm as WasmPolyComm,
        srs::fp::NapiFpSrs as WasmFpSrs,
        wrappers::{field::NapiPastaFp as WasmPastaFp, group::NapiGVesta as WasmGVesta},
    };
    // use arkworks::WasmGVesta;
    use mina_curves::pasta::{Fp, Pallas as GAffineOther, Vesta as GAffine};

    impl_verification_key!(
        caml_pasta_fp_plonk_verifier_index,
        WasmGVesta,
        GAffine,
        WasmPastaFp,
        Fp,
        WasmPolyComm,
        WasmFpSrs,
        GAffineOther,
        mina_poseidon::pasta::fp_kimchi,
        mina_poseidon::pasta::fq_kimchi,
        WasmPastaFpPlonkIndex,
        Fp
    );
}

pub mod fq {
    use super::*;
    use crate::{
        pasta_fq_plonk_index::WasmPastaFqPlonkIndex,
        poly_comm::pallas::NapiFqPolyComm as WasmPolyComm,
        srs::fq::NapiFqSrs as WasmFqSrs,
        wrappers::{field::NapiPastaFq as WasmPastaFq, group::NapiGPallas as WasmGPallas},
    };
    // use arkworks::WasmGPallas;
    use mina_curves::pasta::{Fq, Pallas as GAffine, Vesta as GAffineOther};

    impl_verification_key!(
        caml_pasta_fq_plonk_verifier_index,
        WasmGPallas,
        GAffine,
        WasmPastaFq,
        Fq,
        WasmPolyComm,
        WasmFqSrs,
        GAffineOther,
        mina_poseidon::pasta::fq_kimchi,
        mina_poseidon::pasta::fp_kimchi,
        WasmPastaFqPlonkIndex,
        Fq
    );
}
