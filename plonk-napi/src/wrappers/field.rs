use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::*;
use wasm_types::FlatVectorElem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WasmPastaFp(pub Fp);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WasmPastaFq(pub Fq);

macro_rules! impl_field_wrapper {
    ($name:ident, $field:ty) => {
        impl $name {
            fn serialize(&self) -> Vec<u8> {
                let mut bytes = Vec::with_capacity(core::mem::size_of::<$field>());
                self.0
                    .serialize_compressed(&mut bytes)
                    .expect("serialization failure");
                bytes
            }

            fn deserialize(bytes: &[u8]) -> Self {
                let value =
                    <$field>::deserialize_compressed(bytes).expect("deserialization failure");
                Self(value)
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
                self.serialize()
            }

            fn unflatten(flat: Vec<u8>) -> Self {
                Self::deserialize(&flat)
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
                <Buffer as ValidateNapiValue>::validate(env, napi_val)
            }
        }

        impl FromNapiValue for $name {
            unsafe fn from_napi_value(
                env: sys::napi_env,
                napi_val: sys::napi_value,
            ) -> Result<Self> {
                let buffer = <Buffer as FromNapiValue>::from_napi_value(env, napi_val)?;
                Ok(Self::deserialize(buffer.as_ref()))
            }
        }

        impl ToNapiValue for $name {
            unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
                let buffer = Buffer::from(val.serialize());
                <Buffer as ToNapiValue>::to_napi_value(env, buffer)
            }
        }
    };
}

impl_field_wrapper!(WasmPastaFp, Fp);
impl_field_wrapper!(WasmPastaFq, Fq);
