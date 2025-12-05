use napi::{bindgen_prelude::*, sys};
use serde::{Deserialize, Serialize};
use std::{iter::FromIterator, ops::Deref};
use wasm_types::{FlatVector, FlatVectorElem};

#[derive(Clone, Debug, Default)]
pub struct NapiFlatVector<T>(pub Vec<T>);

impl<T> NapiFlatVector<T> {
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: FlatVectorElem> NapiFlatVector<T> {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let flat: FlatVector<T> = FlatVector::from_bytes(bytes);
        NapiFlatVector(flat.into())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
            .into_iter()
            .flat_map(FlatVectorElem::flatten)
            .collect()
    }
}

impl<T> Deref for NapiFlatVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for NapiFlatVector<T> {
    fn from(value: Vec<T>) -> Self {
        NapiFlatVector(value)
    }
}

impl<T> From<NapiFlatVector<T>> for Vec<T> {
    fn from(value: NapiFlatVector<T>) -> Self {
        value.0
    }
}

impl<T> From<FlatVector<T>> for NapiFlatVector<T> {
    fn from(value: FlatVector<T>) -> Self {
        NapiFlatVector(value.into())
    }
}

impl<T> From<NapiFlatVector<T>> for FlatVector<T> {
    fn from(value: NapiFlatVector<T>) -> Self {
        FlatVector::from(value.0)
    }
}

impl<'a, T> From<&'a NapiFlatVector<T>> for &'a Vec<T> {
    fn from(value: &'a NapiFlatVector<T>) -> Self {
        &value.0
    }
}

impl<T> IntoIterator for NapiFlatVector<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NapiFlatVector<T> {
    type Item = &'a T;
    type IntoIter = <&'a Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> FromIterator<T> for NapiFlatVector<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        NapiFlatVector(Vec::from_iter(iter))
    }
}

impl<T> Extend<T> for NapiFlatVector<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl<T> TypeName for NapiFlatVector<T>
where
    Vec<u8>: TypeName,
{
    fn type_name() -> &'static str {
        <Vec<u8> as TypeName>::type_name()
    }

    fn value_type() -> ValueType {
        <Vec<u8> as TypeName>::value_type()
    }
}

impl<T> ValidateNapiValue for NapiFlatVector<T>
where
    Vec<u8>: ValidateNapiValue,
{
    unsafe fn validate(env: sys::napi_env, napi_val: sys::napi_value) -> Result<sys::napi_value> {
        <Vec<u8> as ValidateNapiValue>::validate(env, napi_val)
    }
}

impl<T> FromNapiValue for NapiFlatVector<T>
where
    T: FlatVectorElem,
{
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        let bytes = <Vec<u8> as FromNapiValue>::from_napi_value(env, napi_val)?;
        Ok(NapiFlatVector::from_bytes(bytes))
    }
}

impl<T> ToNapiValue for NapiFlatVector<T>
where
    T: FlatVectorElem,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        let bytes = val.into_bytes();
        <Vec<u8> as ToNapiValue>::to_napi_value(env, bytes)
    }
}

impl<'a, T> ToNapiValue for &'a NapiFlatVector<T>
where
    T: FlatVectorElem + Clone,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        let bytes = val
            .0
            .clone()
            .into_iter()
            .flat_map(FlatVectorElem::flatten)
            .collect::<Vec<_>>();
        <Vec<u8> as ToNapiValue>::to_napi_value(env, bytes)
    }
}

impl<'a, T> ToNapiValue for &'a mut NapiFlatVector<T>
where
    T: FlatVectorElem + Clone,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        let bytes = val
            .0
            .clone()
            .into_iter()
            .flat_map(FlatVectorElem::flatten)
            .collect::<Vec<_>>();
        <Vec<u8> as ToNapiValue>::to_napi_value(env, bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NapiVector<T>(pub Vec<T>);

impl<T> NapiVector<T> {
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for NapiVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for NapiVector<T> {
    fn from(value: Vec<T>) -> Self {
        NapiVector(value)
    }
}

impl<T> From<NapiVector<T>> for Vec<T> {
    fn from(value: NapiVector<T>) -> Self {
        value.0
    }
}

impl<'a, T> From<&'a NapiVector<T>> for &'a Vec<T> {
    fn from(value: &'a NapiVector<T>) -> Self {
        &value.0
    }
}

impl<T> IntoIterator for NapiVector<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NapiVector<T> {
    type Item = &'a T;
    type IntoIter = <&'a Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> FromIterator<T> for NapiVector<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        NapiVector(Vec::from_iter(iter))
    }
}

impl<T> Extend<T> for NapiVector<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl<T> TypeName for NapiVector<T>
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

impl<T> ValidateNapiValue for NapiVector<T>
where
    Vec<T>: ValidateNapiValue,
    T: FromNapiValue,
{
    unsafe fn validate(env: sys::napi_env, napi_val: sys::napi_value) -> Result<sys::napi_value> {
        <Vec<T> as ValidateNapiValue>::validate(env, napi_val)
    }
}

impl<T> FromNapiValue for NapiVector<T>
where
    Vec<T>: FromNapiValue,
{
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        Ok(NapiVector(<Vec<T> as FromNapiValue>::from_napi_value(
            env, napi_val,
        )?))
    }
}

impl<T> ToNapiValue for NapiVector<T>
where
    Vec<T>: ToNapiValue,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        <Vec<T> as ToNapiValue>::to_napi_value(env, val.0)
    }
}

impl<'a, T> ToNapiValue for &'a NapiVector<T>
where
    Vec<T>: ToNapiValue,
    T: Clone,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        let cloned: Vec<T> = val.0.clone();
        <Vec<T> as ToNapiValue>::to_napi_value(env, cloned)
    }
}

impl<'a, T> ToNapiValue for &'a mut NapiVector<T>
where
    Vec<T>: ToNapiValue,
    T: Clone,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        let cloned: Vec<T> = val.0.clone();
        <Vec<T> as ToNapiValue>::to_napi_value(env, cloned)
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
                $name(Vec::with_capacity(capacity as usize))
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

        impl FromNapiValue for $name {
            unsafe fn from_napi_value(
                env: sys::napi_env,
                napi_val: sys::napi_value,
            ) -> Result<Self> {
                let instance =
                    <ClassInstance<$name> as FromNapiValue>::from_napi_value(env, napi_val)?;
                Ok((*instance).clone())
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
        /*
        impl FromNapiValue for $name {
            unsafe fn from_napi_value(
                env: sys::napi_env,
                napi_val: sys::napi_value,
            ) -> Result<Self> {
                let instance =
                    <ClassInstance<$name> as FromNapiValue>::from_napi_value(env, napi_val)?;
                Ok((*instance).clone())
            }
        }
        */
    };
}

pub mod fp {
    use super::*;
    use crate::wrappers::field::NapiPastaFp;
    use mina_curves::pasta::Fp;
    use napi_derive::napi;

    impl_vec_vec_fp!(WasmVecVecFp, Fp, NapiPastaFp);
}

pub mod fq {
    use super::*;
    use crate::wrappers::field::NapiPastaFq;
    use mina_curves::pasta::Fq;
    use napi_derive::napi;

    impl_vec_vec_fp!(WasmVecVecFq, Fq, NapiPastaFq);
}
