use kimchi::circuits::{
    constraints::FeatureFlags,
    lookup::lookups::{LookupFeatures, LookupPatterns},
};
use napi_derive::napi;

#[napi(object, js_name = "WasmFeatureFlags")]
#[derive(Clone, Copy, Debug, Default)]
pub struct NapiFeatureFlags {
    #[napi(js_name = "range_check0")]
    pub range_check0: bool,
    #[napi(js_name = "range_check1")]
    pub range_check1: bool,
    #[napi(js_name = "foreign_field_add")]
    pub foreign_field_add: bool,
    #[napi(js_name = "foreign_field_mul")]
    pub foreign_field_mul: bool,
    pub xor: bool,
    pub rot: bool,
    pub lookup: bool,
    #[napi(js_name = "runtime_tables")]
    pub runtime_tables: bool,
}

impl From<FeatureFlags> for NapiFeatureFlags {
    fn from(value: FeatureFlags) -> Self {
        let LookupPatterns {
            xor,
            lookup,
            range_check,
            foreign_field_mul,
        } = value.lookup_features.patterns;

        Self {
            range_check0: value.range_check0,
            range_check1: value.range_check1,
            foreign_field_add: value.foreign_field_add,
            foreign_field_mul: value.foreign_field_mul,
            xor: value.xor,
            rot: value.rot,
            lookup: lookup || range_check || foreign_field_mul || xor,
            runtime_tables: value.lookup_features.uses_runtime_tables,
        }
    }
}

impl From<NapiFeatureFlags> for FeatureFlags {
    fn from(value: NapiFeatureFlags) -> Self {
        FeatureFlags {
            range_check0: value.range_check0,
            range_check1: value.range_check1,
            foreign_field_add: value.foreign_field_add,
            foreign_field_mul: value.foreign_field_mul,
            xor: value.xor,
            rot: value.rot,
            lookup_features: LookupFeatures {
                patterns: LookupPatterns {
                    xor: value.lookup && value.xor,
                    lookup: value.lookup,
                    range_check: value.lookup && (value.range_check0 || value.range_check1),
                    foreign_field_mul: value.lookup && value.foreign_field_mul,
                },
                joint_lookup_used: value.lookup,
                uses_runtime_tables: value.runtime_tables,
            },
        }
    }
}
