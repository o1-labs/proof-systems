use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::*;
use serde::{Deserialize, Serialize};
use wasm_types::FlatVectorElem;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct NapiPastaFp(pub Fp);

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct NapiPastaFq(pub Fq);

macro_rules! impl_field_wrapper {
    ($name:ident, $field:ty) => {
        impl $name {
            fn from_bytes(bytes: &[u8]) -> Self {
                let value =
                    <$field>::deserialize_compressed(bytes).expect("deserialization failure");
                Self(value)
            }

            fn to_bytes(&self) -> Vec<u8> {
                let mut bytes = Vec::with_capacity(core::mem::size_of::<$field>());
                self.0
                    .serialize_compressed(&mut bytes)
                    .expect("serialization failure");
                bytes
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
                <$field>::deserialize_compressed(bytes.as_slice())
                    .map(Self)
                    .map_err(serde::de::Error::custom)
            }
        }

        impl From<$field> for $name {
            fn from(value: $field) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $field {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl<'a> From<&'a $name> for &'a $field {
            fn from(value: &'a $name) -> Self {
                &value.0
            }
        }

        impl FlatVectorElem for $name {
            const FLATTENED_SIZE: usize = core::mem::size_of::<$field>();

            fn flatten(self) -> Vec<u8> {
                self.to_bytes()
            }

            fn unflatten(flat: Vec<u8>) -> Self {
                Self::from_bytes(&flat)
            }
        }

        impl TypeName for $name {
            fn type_name() -> &'static str {
                <Buffer as TypeName>::type_name()
            }

            fn value_type() -> ValueType {
                <Buffer as TypeName>::value_type()
            }
        }

        impl ValidateNapiValue for $name {
            unsafe fn validate(
                env: sys::napi_env,
                napi_val: sys::napi_value,
            ) -> Result<sys::napi_value> {
                if <Uint8Array as ValidateNapiValue>::validate(env, napi_val).is_ok() {
                    return Ok(napi_val);
                }
                <Buffer as ValidateNapiValue>::validate(env, napi_val)
            }
        }

        impl FromNapiValue for $name {
            unsafe fn from_napi_value(
                env: sys::napi_env,
                napi_val: sys::napi_value,
            ) -> Result<Self> {
                if let Ok(arr) = <Uint8Array as FromNapiValue>::from_napi_value(env, napi_val) {
                    return Ok(Self::from_bytes(arr.as_ref()));
                }
                let buffer = <Buffer as FromNapiValue>::from_napi_value(env, napi_val)?;
                Ok(Self::from_bytes(buffer.as_ref()))
            }
        }

        impl ToNapiValue for $name {
            unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
                let buffer = Buffer::from(val.to_bytes());
                <Buffer as ToNapiValue>::to_napi_value(env, buffer)
            }
        }

        impl<'a> ToNapiValue for &'a mut $name {
            unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
                let buffer = Buffer::from(val.to_bytes());
                <Buffer as ToNapiValue>::to_napi_value(env, buffer)
            }
        }
    };
}

impl_field_wrapper!(NapiPastaFp, Fp);
impl_field_wrapper!(NapiPastaFq, Fq);
