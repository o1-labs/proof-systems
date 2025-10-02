use kimchi::circuits::lookup::{
    lookups::{
        LookupFeatures as KimchiLookupFeatures, LookupInfo as KimchiLookupInfo,
        LookupPatterns as KimchiLookupPatterns,
    },
    runtime_tables::{
        RuntimeTable as KimchiRuntimeTable, RuntimeTableCfg as KimchiRuntimeTableCfg,
    },
    tables::LookupTable as KimchiLookupTable,
};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use paste::paste;
use wasm_types::{FlatVector, FlatVectorElem};

use crate::{
    wasm_vector::{fp::WasmVecVecFp, fq::WasmVecVecFq},
    wrappers::field::{WasmPastaFp, WasmPastaFq},
};

// -----------------
// Lookup pattern and info wrappers
// -----------------

#[napi(object)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NapiLookupPatterns {
    pub xor: bool,
    pub lookup: bool,
    pub range_check: bool,
    pub foreign_field_mul: bool,
}

impl From<KimchiLookupPatterns> for NapiLookupPatterns {
    fn from(value: KimchiLookupPatterns) -> Self {
        Self {
            xor: value.xor,
            lookup: value.lookup,
            range_check: value.range_check,
            foreign_field_mul: value.foreign_field_mul,
        }
    }
}

impl From<NapiLookupPatterns> for KimchiLookupPatterns {
    fn from(value: NapiLookupPatterns) -> Self {
        KimchiLookupPatterns {
            xor: value.xor,
            lookup: value.lookup,
            range_check: value.range_check,
            foreign_field_mul: value.foreign_field_mul,
        }
    }
}

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NapiLookupFeatures {
    pub patterns: NapiLookupPatterns,
    pub joint_lookup_used: bool,
    pub uses_runtime_tables: bool,
}

impl From<KimchiLookupFeatures> for NapiLookupFeatures {
    fn from(value: KimchiLookupFeatures) -> Self {
        Self {
            patterns: value.patterns.into(),
            joint_lookup_used: value.joint_lookup_used,
            uses_runtime_tables: value.uses_runtime_tables,
        }
    }
}

impl From<NapiLookupFeatures> for KimchiLookupFeatures {
    fn from(value: NapiLookupFeatures) -> Self {
        KimchiLookupFeatures {
            patterns: value.patterns.into(),
            joint_lookup_used: value.joint_lookup_used,
            uses_runtime_tables: value.uses_runtime_tables,
        }
    }
}

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NapiLookupInfo {
    pub max_per_row: u32,
    pub max_joint_size: u32,
    pub features: NapiLookupFeatures,
}

impl From<KimchiLookupInfo> for NapiLookupInfo {
    fn from(value: KimchiLookupInfo) -> Self {
        Self {
            max_per_row: value.max_per_row as u32,
            max_joint_size: value.max_joint_size as u32,
            features: value.features.into(),
        }
    }
}

impl From<NapiLookupInfo> for KimchiLookupInfo {
    fn from(value: NapiLookupInfo) -> Self {
        KimchiLookupInfo {
            max_per_row: value.max_per_row as usize,
            max_joint_size: value.max_joint_size,
            features: value.features.into(),
        }
    }
}

// -----------------
// Lookup tables & runtime tables
// -----------------

macro_rules! impl_lookup_wrappers {
    ($name:ident, $field:ty, $wasm_field:ty, $vec_vec:ty) => {
        paste! {
            #[napi]
            #[derive(Clone)]
            pub struct [<NapiLookupTable $name:camel>] {
                id: i32,
                data: $vec_vec,
            }

            #[napi]
            impl [<NapiLookupTable $name:camel>] {
                #[napi(constructor)]
                pub fn new(id: i32, data: External<$vec_vec>) -> Self {
                    Self {
                        id,
                        data: data.as_ref().clone(),
                    }
                }

                #[napi(getter)]
                pub fn id(&self) -> i32 {
                    self.id
                }

                #[napi(setter)]
                pub fn set_id(&mut self, id: i32) {
                    self.id = id;
                }

                #[napi(getter)]
                pub fn data(&self) -> External<$vec_vec> {
                    External::new(self.data.clone())
                }

                #[napi(setter)]
                pub fn set_data(&mut self, data: External<$vec_vec>) {
                    self.data = data.as_ref().clone();
                }
            }

            impl From<KimchiLookupTable<$field>> for [<NapiLookupTable $name:camel>] {
                fn from(value: KimchiLookupTable<$field>) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into(),
                    }
                }
            }

            impl From<[<NapiLookupTable $name:camel>]> for KimchiLookupTable<$field> {
                fn from(value: [<NapiLookupTable $name:camel>]) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into(),
                    }
                }
            }

            #[napi]
            #[derive(Clone)]
            pub struct [<NapiRuntimeTableCfg $name:camel>] {
                id: i32,
                first_column: Vec<$field>,
            }

            #[napi]
            impl [<NapiRuntimeTableCfg $name:camel>] {
                #[napi(constructor)]
                pub fn new(id: i32, first_column: Uint8Array) -> Result<Self> {
                    let bytes = first_column.as_ref().to_vec();
                    let elements: Vec<$field> = FlatVector::<$wasm_field>::from_bytes(bytes)
                        .into_iter()
                        .map(Into::into)
                        .collect();
                    Ok(Self { id, first_column: elements })
                }

                #[napi(getter)]
                pub fn id(&self) -> i32 {
                    self.id
                }

                #[napi(setter)]
                pub fn set_id(&mut self, id: i32) {
                    self.id = id;
                }

                #[napi(getter)]
                pub fn first_column(&self) -> Result<Uint8Array> {
                    let mut bytes = Vec::with_capacity(self.first_column.len() * <$wasm_field>::FLATTENED_SIZE);
                    for value in &self.first_column {
                        let element = <$wasm_field>::from(*value);
                        bytes.extend(element.flatten());
                    }
                    Ok(Uint8Array::from(bytes))
                }
            }

            impl From<KimchiRuntimeTableCfg<$field>> for [<NapiRuntimeTableCfg $name:camel>] {
                fn from(value: KimchiRuntimeTableCfg<$field>) -> Self {
                    Self {
                        id: value.id,
                        first_column: value.first_column,
                    }
                }
            }

            impl From<[<NapiRuntimeTableCfg $name:camel>]> for KimchiRuntimeTableCfg<$field> {
                fn from(value: [<NapiRuntimeTableCfg $name:camel>]) -> Self {
                    Self {
                        id: value.id,
                        first_column: value.first_column,
                    }
                }
            }

            #[napi]
            #[derive(Clone)]
            pub struct [<NapiRuntimeTable $name:camel>] {
                id: i32,
                data: Vec<$field>,
            }

            #[napi]
            impl [<NapiRuntimeTable $name:camel>] {
                #[napi(constructor)]
                pub fn new(id: i32, data: Uint8Array) -> Result<Self> {
                    let bytes = data.as_ref().to_vec();
                    let elements: Vec<$field> = FlatVector::<$wasm_field>::from_bytes(bytes)
                        .into_iter()
                        .map(Into::into)
                        .collect();
                    Ok(Self { id, data: elements })
                }

                #[napi(getter)]
                pub fn id(&self) -> i32 {
                    self.id
                }

                #[napi(setter)]
                pub fn set_id(&mut self, id: i32) {
                    self.id = id;
                }

                #[napi(getter)]
                pub fn data(&self) -> Result<Uint8Array> {
                    let mut bytes = Vec::with_capacity(self.data.len() * <$wasm_field>::FLATTENED_SIZE);
                    for value in &self.data {
                        let element = <$wasm_field>::from(*value);
                        bytes.extend(element.flatten());
                    }
                    Ok(Uint8Array::from(bytes))
                }
            }

            impl From<KimchiRuntimeTable<$field>> for [<NapiRuntimeTable $name:camel>] {
                fn from(value: KimchiRuntimeTable<$field>) -> Self {
                    Self {
                        id: value.id,
                        data: value.data,
                    }
                }
            }

            impl From<[<NapiRuntimeTable $name:camel>]> for KimchiRuntimeTable<$field> {
                fn from(value: [<NapiRuntimeTable $name:camel>]) -> Self {
                    Self {
                        id: value.id,
                        data: value.data,
                    }
                }
            }
        }
    };
}

impl_lookup_wrappers!(Fp, Fp, WasmPastaFp, WasmVecVecFp);
impl_lookup_wrappers!(Fq, Fq, WasmPastaFq, WasmVecVecFq);
