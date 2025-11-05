use crate::{
    vector::{fp::NapiVecVecFp, fq::NapiVecVecFq},
    wrappers::field::{NapiPastaFp, NapiPastaFq},
};
use kimchi::circuits::lookup::{
    lookups::{LookupFeatures, LookupInfo, LookupPatterns},
    runtime_tables::{RuntimeTable, RuntimeTableCfg},
    tables::LookupTable,
};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use paste::paste;
use serde::{Deserialize, Serialize};
use wasm_types::{FlatVector, FlatVectorElem};

// -----------------
// Lookup pattern and info wrappers
// -----------------

#[napi(object)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct NapiLookupPatterns {
    pub xor: bool,
    pub lookup: bool,
    pub range_check: bool,
    pub foreign_field_mul: bool,
}

impl From<LookupPatterns> for NapiLookupPatterns {
    fn from(value: LookupPatterns) -> Self {
        Self {
            xor: value.xor,
            lookup: value.lookup,
            range_check: value.range_check,
            foreign_field_mul: value.foreign_field_mul,
        }
    }
}

impl From<NapiLookupPatterns> for LookupPatterns {
    fn from(value: NapiLookupPatterns) -> Self {
        LookupPatterns {
            xor: value.xor,
            lookup: value.lookup,
            range_check: value.range_check,
            foreign_field_mul: value.foreign_field_mul,
        }
    }
}

#[napi(object)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NapiLookupFeatures {
    pub patterns: NapiLookupPatterns,
    pub joint_lookup_used: bool,
    pub uses_runtime_tables: bool,
}

impl From<LookupFeatures> for NapiLookupFeatures {
    fn from(value: LookupFeatures) -> Self {
        Self {
            patterns: value.patterns.into(),
            joint_lookup_used: value.joint_lookup_used,
            uses_runtime_tables: value.uses_runtime_tables,
        }
    }
}

impl From<NapiLookupFeatures> for LookupFeatures {
    fn from(value: NapiLookupFeatures) -> Self {
        LookupFeatures {
            patterns: value.patterns.into(),
            joint_lookup_used: value.joint_lookup_used,
            uses_runtime_tables: value.uses_runtime_tables,
        }
    }
}

#[napi(object)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NapiLookupInfo {
    pub max_per_row: i32,
    pub max_joint_size: i32,
    pub features: NapiLookupFeatures,
}

impl From<LookupInfo> for NapiLookupInfo {
    fn from(value: LookupInfo) -> Self {
        Self {
            max_per_row: value.max_per_row as i32,
            max_joint_size: value.max_joint_size as i32,
            features: value.features.into(),
        }
    }
}

impl From<NapiLookupInfo> for LookupInfo {
    fn from(value: NapiLookupInfo) -> Self {
        LookupInfo {
            max_per_row: value.max_per_row as usize,
            max_joint_size: value.max_joint_size as u32,
            features: value.features.into(),
        }
    }
}

// -----------------
// Lookup tables & runtime tables
// -----------------

macro_rules! impl_lookup_wrappers {
    ($name:ident, $field:ty, $NapiF:ty, $vec_vec:ty) => {
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
                pub fn new(id: i32, data: $vec_vec) -> Self {
                    Self {
                        id,
                        data: data.clone(),
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
                pub fn data(&self) -> $vec_vec {
                    self.data.clone()
                }

                #[napi(setter)]
                pub fn set_data(&mut self, data: $vec_vec) {
                    self.data = data.clone();
                }
            }

            impl From<LookupTable<$field>> for [<NapiLookupTable $name:camel>] {
                fn from(value: LookupTable<$field>) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into(),
                    }
                }
            }

            impl From<[<NapiLookupTable $name:camel>]> for LookupTable<$field> {
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
                    let elements: Vec<$field> = FlatVector::<$NapiF>::from_bytes(bytes)
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
                    let mut bytes = Vec::with_capacity(self.first_column.len() * <$NapiF>::FLATTENED_SIZE);
                    for value in &self.first_column {
                        let element = <$NapiF>::from(*value);
                        bytes.extend(element.flatten());
                    }
                    Ok(Uint8Array::from(bytes))
                }
            }

            impl From<RuntimeTableCfg<$field>> for [<NapiRuntimeTableCfg $name:camel>] {
                fn from(value: RuntimeTableCfg<$field>) -> Self {
                    Self {
                        id: value.id,
                        first_column: value.first_column,
                    }
                }
            }

            impl From<[<NapiRuntimeTableCfg $name:camel>]> for RuntimeTableCfg<$field> {
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
                    let elements: Vec<$field> = FlatVector::<$NapiF>::from_bytes(bytes)
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
                    let mut bytes = Vec::with_capacity(self.data.len() * <$NapiF>::FLATTENED_SIZE);
                    for value in &self.data {
                        let element = <$NapiF>::from(*value);
                        bytes.extend(element.flatten());
                    }
                    Ok(Uint8Array::from(bytes))
                }
            }

            impl From<RuntimeTable<$field>> for [<NapiRuntimeTable $name:camel>] {
                fn from(value: RuntimeTable<$field>) -> Self {
                    Self {
                        id: value.id,
                        data: value.data,
                    }
                }
            }

            impl From<[<NapiRuntimeTable $name:camel>]> for RuntimeTable<$field> {
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

impl_lookup_wrappers!(Fp, Fp, NapiPastaFp, NapiVecVecFp);
impl_lookup_wrappers!(Fq, Fq, NapiPastaFq, NapiVecVecFq);
