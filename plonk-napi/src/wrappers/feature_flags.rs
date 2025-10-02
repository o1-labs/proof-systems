use kimchi::circuits::{
    constraints::FeatureFlags as KimchiFeatureFlags,
    lookup::lookups::{LookupFeatures, LookupPatterns},
};
use napi_derive::napi;

#[napi(object)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NapiFeatureFlags {
    pub range_check0: bool,
    pub range_check1: bool,
    pub foreign_field_add: bool,
    pub foreign_field_mul: bool,
    pub xor: bool,
    pub rot: bool,
    pub lookup: bool,
    pub runtime_tables: bool,
}

impl From<KimchiFeatureFlags> for NapiFeatureFlags {
    fn from(value: KimchiFeatureFlags) -> Self {
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

impl From<NapiFeatureFlags> for KimchiFeatureFlags {
    fn from(value: NapiFeatureFlags) -> Self {
        KimchiFeatureFlags {
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