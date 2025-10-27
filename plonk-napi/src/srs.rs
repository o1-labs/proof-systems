use crate::{
    poly_comm::{pallas::WasmFqPolyComm, vesta::WasmFpPolyComm},
    wasm_vector::WasmVector,
    wrappers::{
        field::{WasmPastaFp, WasmPastaFq},
        group::{WasmGPallas, WasmGVesta},
    },
};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations};
use core::ops::Deref;
use mina_curves::pasta::{Pallas as GAffineOther, Vesta as GAffine};
use napi::bindgen_prelude::{Error, External, Result, Status, Uint8Array};
use napi_derive::napi;
use paste::paste;
use poly_commitment::{
    commitment::b_poly_coefficients, hash_map_cache::HashMapCache, ipa::SRS, SRS as ISRS,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom},
    sync::Arc,
};
use wasm_types::FlatVector as WasmFlatVector;

/*
#[napi]
pub fn caml_fp_srs_to_bytes(srs: External<WasmSrsFp>) -> NapiResult<Uint8Array> {
    let buffer = rmp_serde::to_vec(srs.as_ref().0.as_ref())
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Uint8Array::from(buffer))
}

#[napi]
pub fn caml_fp_srs_from_bytes(bytes: Uint8Array) -> NapiResult<External<WasmSrsFp>> {
    let srs: SRS<GAffine> = rmp_serde::from_slice(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(External::new(Arc::new(srs).into()))
}

#[napi]
pub fn caml_fq_srs_from_bytes(bytes: Uint8Array) -> NapiResult<External<WasmSrsFq>> {
    let srs: SRS<GAffineOther> = rmp_serde::from_slice(bytes.as_ref())
        .map_err(|e: rmp_serde::decode::Error| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(External::new(Arc::new(srs).into()))
}
*/

macro_rules! impl_srs {
    (
        $name:ident,
        $field_ty:ty,
        $wasmF:ty,
        $group_ty:ty,
        $group_wrapper:ty,
        $poly_comm_wrapper:ty,
        $field_name:ident
    ) => {
        paste! {

            type WasmPolyComm = $poly_comm_wrapper;

            #[napi]
            #[derive(Clone)]
            pub struct [<Napi $field_name:camel Srs>] (
                 #[napi(skip)] pub Arc<SRS<$group_ty>>
            );

            impl Deref for [<Napi $field_name:camel Srs>] {
                type Target = Arc<SRS<$group_ty>>;

                fn deref(&self) -> &Self::Target { &self.0 }
            }

            impl From<Arc<SRS<$group_ty>>> for [<Napi $field_name:camel Srs>] {
                fn from(x: Arc<SRS<$group_ty>>) -> Self {
                    [<Napi $field_name:camel Srs>](x)
                }
            }

            impl From<&Arc<SRS<$group_ty>>> for [<Napi $field_name:camel Srs>] {
                fn from(x: &Arc<SRS<$group_ty>>) -> Self {
                    [<Napi $field_name:camel Srs>](x.clone())
                }
            }

            impl From<[<Napi $field_name:camel Srs>]> for Arc<SRS<$group_ty>> {
                fn from(x: [<Napi $field_name:camel Srs>]) -> Self {
                    x.0
                }
            }

            impl From<&[<Napi $field_name:camel Srs>]> for Arc<SRS<$group_ty>> {
                fn from(x: &[<Napi $field_name:camel Srs>]) -> Self {
                    x.0.clone()
                }
            }

            impl<'a> From<&'a [<Napi $field_name:camel Srs>]> for &'a Arc<SRS<$group_ty>> {
                fn from(x: &'a [<Napi $field_name:camel Srs>]) -> Self {
                    &x.0
                }
            }

            /*
            impl [<Napi $field_name:camel Srs>] {
                fn new(inner: SRS<$group_ty>) -> Self {
                    Self (
                        Arc::new(inner),
                    )
                }

                fn from_arc(inner: Arc<SRS<$group_ty>>) -> Self {
                    Self (inner)
                }
            }
            */

            fn invalid_domain_error() -> Error {
                Error::new(Status::InvalidArg, "invalid domain size")
            }

            fn map_error(context: &str, err: impl std::fmt::Display) -> Error {
                Error::new(Status::GenericFailure, format!("{}: {}", context, err))
            }

            #[napi]
            impl [<Napi $field_name:camel Srs>] {

                #[napi]
                pub fn serialize(&self) -> Result<Uint8Array> {
                    let mut buf = Vec::new();
                    self.0
                        .serialize(&mut rmp_serde::Serializer::new(&mut buf))
                        .map_err(|e| map_error("srs_serialize", e))?;
                    Ok(Uint8Array::from(buf))
                }

                #[napi]
                pub fn deserialize(bytes: Uint8Array) -> Result<Self> {
                    let srs: SRS<$group_ty> = rmp_serde::from_slice(bytes.as_ref())
                        .map_err(|e| map_error("srs_deserialize", e))?;
                    Ok(Arc::new(srs).into())
                }

                #[napi(factory)]
                pub fn [<caml_ $name:snake _srs_create>](depth: i32) -> Result<Self> {
                    Ok(Arc::new(SRS::<$group_ty>::create(depth as usize)).into())
                }

                #[napi(factory)]
                pub fn [<caml_ $name:snake _srs_create_parallel>](depth: i32) -> Result<Self> {
                    Ok(Arc::new(SRS::<$group_ty>::create_parallel(
                        depth as usize,
                    )).into())
                }

                #[napi]
                pub fn [<caml_ $name:snake _get>](srs: &[<Napi $field_name:camel Srs>]) -> Vec<$group_wrapper> {
                    let mut h_and_gs: Vec<$group_wrapper> = vec![srs.0.h.into()];
                    h_and_gs.extend(srs.0.g.iter().cloned().map(Into::into));
                    h_and_gs
                }

                #[napi]
                pub fn [<caml_ $name:snake _add_lagrange_basis>](srs: &[<Napi $field_name:camel Srs>], log2_size: i32) -> Result<()> {
                    let size = 1usize << (log2_size as usize);
                    let domain = EvaluationDomain::<$field_ty>::new(size).ok_or_else(invalid_domain_error)?;
                    srs.get_lagrange_basis(domain);
                    Ok(())
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_write>](append: Option<bool>, srs: &[<Napi $field_name:camel Srs>], path: String) -> Result<()> {
                    let function_name = format!("caml_{0}_srs_write", stringify!($name).to_lowercase());
                    let file = OpenOptions::new()
                        .append(append.unwrap_or(true))
                        .open(&path)
                        .map_err(|err| map_error(&function_name, err))?;
                    let file = BufWriter::new(file);
                    srs.0.serialize(&mut rmp_serde::Serializer::new(file))
                        .map_err(|err| map_error(&function_name, err))
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_read>](offset: Option<i32>, path: String) -> Result<Option<Self>> {
                    let function_name = format!("caml_{0}_srs_read", stringify!($name).to_lowercase());
                    let file = match File::open(&path) {
                        Ok(file) => file,
                        Err(err) => return Err(map_error(&function_name, err)),
                    };
                    let mut reader = BufReader::new(file);

                    if let Some(off) = offset {
                        reader
                            .seek(SeekFrom::Start(off as u64))
                            .map_err(|err| map_error(&function_name, err))?;
                    }

                    match SRS::<$group_ty>::deserialize(&mut rmp_serde::Deserializer::new(reader)) {
                        Ok(srs) => Ok(Some(Arc::new(srs).into())),
                        Err(_) => Ok(None),
                    }
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_get>](srs: &[<Napi $field_name:camel Srs>]) -> Vec<$group_wrapper> {
                    let mut h_and_gs: Vec<$group_wrapper> = vec![srs.0.h.into()];
                    h_and_gs.extend(srs.0.g.iter().cloned().map(Into::into));
                    h_and_gs
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_set>](h_and_gs: Vec<$group_wrapper>) -> Result<Self> {
                    let mut h_and_gs: Vec<$group_ty> = h_and_gs.into_iter().map(Into::into).collect();
                    if h_and_gs.is_empty() {
                        return Err(Error::new(
                            Status::InvalidArg,
                            "expected at least one element for SRS",
                        ));
                    }
                    let h = h_and_gs.remove(0);
                    let g = h_and_gs;
                    let srs = SRS::<$group_ty> { h, g, lagrange_bases: HashMapCache::new() };
                    Ok(Arc::new(srs).into())
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_maybe_lagrange_commitment>](
                    srs: &[<Napi $field_name:camel Srs>],
                    domain_size: i32,
                    i: i32,
                ) -> Option<WasmPolyComm> {
                    if !srs
                        .0
                        .lagrange_bases
                        .contains_key(&(domain_size as usize))
                    {
                        return None;
                    }
                    let basis = srs
                        .get_lagrange_basis_from_domain_size(domain_size as usize);
                    Some(basis[i as usize].clone().into())
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_set_lagrange_basis>](srs: &[<Napi $field_name:camel Srs>],
                    domain_size: i32,
                    input_bases: WasmVector<WasmPolyComm>,
                ) {
                    srs.0.lagrange_bases
                        .get_or_generate(domain_size as usize, || input_bases);
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_get_lagrange_basis>](srs: &[<Napi $field_name:camel Srs>],
                    domain_size: i32,
                ) -> Result<WasmVector<WasmPolyComm>> {
                    let domain = EvaluationDomain::<$field_ty>::new(domain_size as usize)
                        .ok_or_else(invalid_domain_error)?;
                    let basis = srs.0.get_lagrange_basis(domain);
                    Ok(basis.iter().cloned().map(Into::into).collect())
                }

                #[napi]
                pub fn [<caml_ $name:snake _srs_commit_evaluations>](srs: &[<Napi $field_name:camel Srs>],
                    domain_size: i32,
                    evals: Uint8Array,
                ) -> Result<WasmPolyComm> {
                    let elems: Vec<$field_ty> = WasmFlatVector::<$wasmF>::from_bytes(
                        evals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let x_domain = EvaluationDomain::<$field_ty>::new(domain_size as usize)
                        .ok_or_else(invalid_domain_error)?;
                    let evals = elems.into_iter().map(Into::into).collect();
                    let p = Evaluations::<$field_ty>::from_vec_and_domain(evals, x_domain).interpolate();
                    Ok(srs.commit_non_hiding(&p, 1).into())
                }

                #[napi]
                pub fn b_poly_commitment(srs: &[<Napi $field_name:camel Srs>], chals: Uint8Array) -> Result<WasmPolyComm> {
                    let elements: Vec<$field_ty> = WasmFlatVector::<$wasmF>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let coeffs = b_poly_coefficients(&elements);
                    let p = DensePolynomial::<$field_ty>::from_coefficients_vec(coeffs);
                    Ok(srs.commit_non_hiding(&p, 1).into())
                }

                #[napi]
                pub fn batch_accumulator_check(
                    srs: &[<Napi $field_name:camel Srs>],
                    comms: WasmVector<$group_wrapper>,
                    chals: Uint8Array,
                ) -> Result<bool> {
                    let comms: Vec<$group_ty> = comms.into_iter().map(Into::into).collect();
                    let chals: Vec<$field_ty> = WasmFlatVector::<$wasmF>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    Ok(poly_commitment::utils::batch_dlog_accumulator_check(
                        &srs,
                        &comms,
                        &chals,
                    ))
                }

                #[napi]
                pub fn batch_accumulator_generate(
                    srs: &[<Napi $field_name:camel Srs>],
                    comms: i32,
                    chals: Uint8Array,
                ) -> Result<WasmVector<$group_wrapper>> {
                    let chals: Vec<$field_ty> = WasmFlatVector::<$wasmF>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let points = poly_commitment::utils::batch_dlog_accumulator_generate::<$group_ty>(
                        &srs,
                        comms as usize,
                        &chals,
                    );
                    Ok(points.into_iter().map(Into::into).collect())
                }

                #[napi]
                pub fn h(srs: &[<Napi $field_name:camel Srs>]) -> $group_wrapper {
                    srs.h.into()
                }
            }
        }
    }
}

pub mod fp {
    use super::*;
    impl_srs!(
        fp,
        mina_curves::pasta::Fp,
        WasmPastaFp,
        mina_curves::pasta::Vesta,
        WasmGVesta,
        WasmFpPolyComm,
        Fp
    );
}

pub mod fq {
    use super::*;
    impl_srs!(
        fq,
        mina_curves::pasta::Fq,
        WasmPastaFq,
        mina_curves::pasta::Pallas,
        WasmGPallas,
        WasmFqPolyComm,
        Fq
    );
}
