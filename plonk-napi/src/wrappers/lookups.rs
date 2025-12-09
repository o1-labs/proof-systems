use crate::{
    vector::{fp::WasmVecVecFp as NapiVecVecFp, fq::WasmVecVecFq as NapiVecVecFq, NapiFlatVector},
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

#[napi(object, js_name = "WasmLookupPatterns")]
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

#[napi(object, js_name = "WasmLookupFeatures")]
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

#[napi(object, js_name = "WasmLookupInfo")]
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
    ($field_name:ident, $field:ty, $NapiF:ty, $vec_vec:ty) => {
        paste! {
            #[napi(js_name = [<"WasmPasta" $field_name:camel "LookupTable">])]
            #[derive(Clone)]
            pub struct [<NapiPasta $field_name:camel LookupTable>] {
                id: i32,
                data: $vec_vec,
            }

            #[napi]
            impl [<NapiPasta $field_name:camel LookupTable>] {
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

            impl From<LookupTable<$field>> for [<NapiPasta $field_name:camel LookupTable>] {
                fn from(value: LookupTable<$field>) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into(),
                    }
                }
            }

            impl From<[<NapiPasta $field_name:camel LookupTable>]> for LookupTable<$field> {
                fn from(value: [<NapiPasta $field_name:camel LookupTable>]) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into(),
                    }
                }
            }

            #[napi(js_name = [<"WasmPasta"  $field_name:camel "RuntimeTableCfg">])]
            #[derive(Clone)]
            pub struct [<NapiPasta $field_name:camel RuntimeTableCfg>] {
                id: i32,
                first_column: Vec<$field>,
            }

            #[napi]
            impl [<NapiPasta $field_name:camel RuntimeTableCfg>] {
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

            impl From<RuntimeTableCfg<$field>> for [<NapiPasta $field_name:camel RuntimeTableCfg>] {
                fn from(value: RuntimeTableCfg<$field>) -> Self {
                    Self {
                        id: value.id,
                        first_column: value.first_column,
                    }
                }
            }

            impl From<[<NapiPasta $field_name:camel RuntimeTableCfg>]> for RuntimeTableCfg<$field> {
                fn from(value: [<NapiPasta $field_name:camel RuntimeTableCfg>]) -> Self {
                    Self {
                        id: value.id,
                        first_column: value.first_column,
                    }
                }
            }

            #[napi(object, js_name = [<"Wasm" $field_name:camel "RuntimeTable">])]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel RuntimeTable>] {
                pub id: i32,
                pub data: NapiFlatVector<$NapiF>,
            }

            impl From<RuntimeTable<$field>> for [<Napi $field_name:camel RuntimeTable>] {
                fn from(value: RuntimeTable<$field>) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into_iter().map(Into::into).collect(),
                    }
                }
            }

            impl From<[<Napi $field_name:camel RuntimeTable>]> for RuntimeTable<$field> {
                fn from(value: [<Napi $field_name:camel RuntimeTable>]) -> Self {
                    Self {
                        id: value.id,
                        data: value.data.into_iter().map(Into::into).collect(),
                    }
                }
            }
        }
    };
}

impl_lookup_wrappers!(Fp, Fp, NapiPastaFp, NapiVecVecFp);
impl_lookup_wrappers!(Fq, Fq, NapiPastaFq, NapiVecVecFq);
