use std::{iter::FromIterator, ops::Deref};

use napi::bindgen_prelude::*;
use napi::sys;
use wasm_types::{FlatVector, FlatVectorElem};

#[derive(Clone, Debug, Default)]
pub struct WasmVector<T>(pub Vec<T>);

impl<T> WasmVector<T> {
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for WasmVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for WasmVector<T> {
    fn from(value: Vec<T>) -> Self {
        WasmVector(value)
    }
}

impl<T> From<WasmVector<T>> for Vec<T> {
    fn from(value: WasmVector<T>) -> Self {
        value.0
    }
}

impl<'a, T> From<&'a WasmVector<T>> for &'a Vec<T> {
    fn from(value: &'a WasmVector<T>) -> Self {
        &value.0
    }
}

impl<T> IntoIterator for WasmVector<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a WasmVector<T> {
    type Item = &'a T;
    type IntoIter = <&'a Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> FromIterator<T> for WasmVector<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        WasmVector(Vec::from_iter(iter))
    }
}

impl<T> Extend<T> for WasmVector<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl<T> TypeName for WasmVector<T>
where
    Vec<T>: TypeName,
{
    fn type_name() -> &'static str {
        <Vec<T> as TypeName>::type_name()
    }

    fn value_type() -> ValueType {
        <Vec<T> as TypeName>::value_type()
    }
}

impl<T> ValidateNapiValue for WasmVector<T>
where
    Vec<T>: ValidateNapiValue,
    T: FromNapiValue,
{
    unsafe fn validate(env: sys::napi_env, napi_val: sys::napi_value) -> Result<sys::napi_value> {
        <Vec<T> as ValidateNapiValue>::validate(env, napi_val)
    }
}

impl<T> FromNapiValue for WasmVector<T>
where
    Vec<T>: FromNapiValue,
{
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        Ok(WasmVector(<Vec<T> as FromNapiValue>::from_napi_value(
            env, napi_val,
        )?))
    }
}

impl<T> ToNapiValue for WasmVector<T>
where
    Vec<T>: ToNapiValue,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        <Vec<T> as ToNapiValue>::to_napi_value(env, val.0)
    }
}

macro_rules! impl_vec_vec_fp {
    ($name:ident, $field:ty, $wasm_field:ty) => {
        #[napi]
        #[derive(Clone, Debug, Default)]
        pub struct $name(#[napi(skip)] pub Vec<Vec<$field>>);

        #[napi]
        impl $name {
            #[napi(constructor)]
            pub fn create(capacity: i32) -> Self {
                Self(Vec::with_capacity(capacity as usize))
            }

            #[napi]
            pub fn push(&mut self, vector: Uint8Array) -> Result<()> {
                let flattened = vector.as_ref().to_vec();
                let values = FlatVector::<$wasm_field>::from_bytes(flattened)
                    .into_iter()
                    .map(Into::into)
                    .collect();
                self.0.push(values);
                Ok(())
            }

            #[napi]
            pub fn get(&self, index: i32) -> Result<Uint8Array> {
                let slice = self.0.get(index as usize).ok_or_else(|| {
                    Error::new(Status::InvalidArg, "index out of bounds".to_string())
                })?;

                let bytes = slice
                    .iter()
                    .cloned()
                    .map(<$wasm_field>::from)
                    .flat_map(FlatVectorElem::flatten)
                    .collect::<Vec<u8>>();

                Ok(Uint8Array::from(bytes))
            }

            #[napi]
            pub fn set(&mut self, index: i32, vector: Uint8Array) -> Result<()> {
                let entry = self.0.get_mut(index as usize).ok_or_else(|| {
                    Error::new(Status::InvalidArg, "index out of bounds".to_string())
                })?;

                let flattened = vector.as_ref().to_vec();
                *entry = FlatVector::<$wasm_field>::from_bytes(flattened)
                    .into_iter()
                    .map(Into::into)
                    .collect();
                Ok(())
            }
        }

        impl From<Vec<Vec<$field>>> for $name {
            fn from(value: Vec<Vec<$field>>) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Vec<Vec<$field>> {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

pub mod fp {
    use super::*;
    use crate::field::WasmPastaFp;
    use mina_curves::pasta::Fp;
    use napi_derive::napi;

    impl_vec_vec_fp!(WasmVecVecFp, Fp, WasmPastaFp);
}

pub mod fq {
    use super::*;
    use crate::field::WasmPastaFq;
    use mina_curves::pasta::Fq;
    use napi_derive::napi;

    impl_vec_vec_fp!(WasmVecVecFq, Fq, WasmPastaFq);
}
