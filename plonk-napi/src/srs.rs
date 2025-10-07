use std::sync::Arc;

use mina_curves::pasta::{Pallas as GAffineOther, Vesta as GAffine};
use napi::bindgen_prelude::{Error, External, Result as NapiResult, Status, Uint8Array};
use napi_derive::napi;
use plonk_wasm::srs::fp::WasmFpSrs as WasmSrsFp;
use plonk_wasm::srs::fq::WasmFqSrs as WasmSrsFq;

use poly_commitment::ipa::SRS;

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
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom},
    sync::Arc,
};

use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use paste::paste;
use poly_commitment::{commitment::b_poly_coefficients, hash_map_cache::HashMapCache, ipa::SRS};
use wasm_types::FlatVector as WasmFlatVector;

use crate::{
    poly_comm::{pallas::WasmFqPolyComm, vesta::WasmFpPolyComm},
    wasm_vector::WasmVector,
    wrappers::field::{WasmPastaFp, WasmPastaFq},
    wrappers::group::{WasmGPallas, WasmGVesta},
};

macro_rules! impl_srs_module {
    (
        $mod_name:ident,
        $field_ty:ty,
        $wasm_field:ty,
        $group_ty:ty,
        $group_wrapper:ty,
        $poly_comm_wrapper:ty,
        $struct_ident:ident
    ) => {
        pub mod $mod_name {
            use super::*;

            #[napi]
            #[derive(Clone)]
            pub struct $struct_ident {
                #[napi(skip)]
                pub inner: Arc<SRS<$group_ty>>,
            }

            impl $struct_ident {
                fn new(inner: SRS<$group_ty>) -> Self {
                    Self {
                        inner: Arc::new(inner),
                    }
                }

                fn from_arc(inner: Arc<SRS<$group_ty>>) -> Self {
                    Self { inner }
                }
            }

            fn invalid_domain_error() -> Error {
                Error::new(Status::InvalidArg, "invalid domain size")
            }

            fn map_error(context: &str, err: impl std::fmt::Display) -> Error {
                Error::new(Status::GenericFailure, format!("{}: {}", context, err))
            }

            #[napi]
            impl $struct_ident {
                #[napi(factory)]
                pub fn create(depth: i32) -> Result<Self> {
                    Ok(Self::from_arc(Arc::new(SRS::<$group_ty>::create(depth as usize))))
                }

                #[napi(factory)]
                pub fn create_parallel(depth: i32) -> Result<Self> {
                    Ok(Self::from_arc(Arc::new(SRS::<$group_ty>::create_parallel(
                        depth as usize,
                    ))))
                }

                #[napi]
                pub fn add_lagrange_basis(&self, log2_size: i32) -> Result<()> {
                    let size = 1usize << (log2_size as usize);
                    let domain = EvaluationDomain::<$field_ty>::new(size).ok_or_else(invalid_domain_error)?;
                    self.inner.get_lagrange_basis(domain);
                    Ok(())
                }

                #[napi]
                pub fn write(&self, append: Option<bool>, path: String) -> Result<()> {
                    let file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .append(append.unwrap_or(true))
                        .open(&path)
                        .map_err(|err| map_error("srs_write", err))?;
                    let mut writer = BufWriter::new(file);
                    self.inner
                        .serialize(&mut rmp_serde::Serializer::new(&mut writer))
                        .map_err(|err| map_error("srs_write", err))
                }

                #[napi]
                pub fn read(offset: Option<i32>, path: String) -> Result<Option<Self>> {
                    let file = match File::open(&path) {
                        Ok(file) => file,
                        Err(err) => return Err(map_error("srs_read", err)),
                    };
                    let mut reader = BufReader::new(file);

                    if let Some(off) = offset {
                        reader
                            .seek(SeekFrom::Start(off as u64))
                            .map_err(|err| map_error("srs_read", err))?;
                    }

                    match SRS::<$group_ty>::deserialize(&mut rmp_serde::Deserializer::new(reader)) {
                        Ok(srs) => Ok(Some(Self::from_arc(Arc::new(srs)))),
                        Err(_) => Ok(None),
                    }
                }

                #[napi]
                pub fn get(&self) -> WasmVector<$group_wrapper> {
                    let mut points: Vec<$group_wrapper> = vec![self.inner.h.into()];
                    points.extend(self.inner.g.iter().cloned().map(Into::into));
                    points.into()
                }

                #[napi]
                pub fn set(points: WasmVector<$group_wrapper>) -> Result<Self> {
                    let mut pts: Vec<$group_ty> = points.into_iter().map(Into::into).collect();
                    if pts.is_empty() {
                        return Err(Error::new(
                            Status::InvalidArg,
                            "expected at least one element for SRS",
                        ));
                    }
                    let h = pts.remove(0);
                    let g = pts;
                    Ok(Self::from_arc(Arc::new(SRS::<$group_ty> {
                        h,
                        g,
                        lagrange_bases: HashMapCache::new(),
                    })))
                }

                #[napi]
                pub fn maybe_lagrange_commitment(
                    &self,
                    domain_size: i32,
                    index: i32,
                ) -> Option<$poly_comm_wrapper> {
                    if !self
                        .inner
                        .lagrange_bases
                        .contains_key(&(domain_size as usize))
                    {
                        return None;
                    }
                    let basis = self
                        .inner
                        .get_lagrange_basis_from_domain_size(domain_size as usize);
                    basis.get(index as usize).cloned().map(Into::into)
                }

                #[napi]
                pub fn set_lagrange_basis(
                    &self,
                    domain_size: i32,
                    bases: WasmVector<$poly_comm_wrapper>,
                ) {
                    let domain = domain_size as usize;
                    let commitments: Vec<_> = bases.into_iter().map(Into::into).collect();
                    self.inner
                        .lagrange_bases
                        .get_or_generate(domain, || commitments.clone());
                }

                #[napi]
                pub fn get_lagrange_basis(
                    &self,
                    domain_size: i32,
                ) -> Result<WasmVector<$poly_comm_wrapper>> {
                    let domain = EvaluationDomain::<$field_ty>::new(domain_size as usize)
                        .ok_or_else(invalid_domain_error)?;
                    let basis = self.inner.get_lagrange_basis(domain);
                    Ok(basis.iter().cloned().map(Into::into).collect())
                }

                #[napi]
                pub fn commit_evaluations(
                    &self,
                    domain_size: i32,
                    evaluations: Uint8Array,
                ) -> Result<$poly_comm_wrapper> {
                    let elems: Vec<$field_ty> = WasmFlatVector::<$wasm_field>::from_bytes(
                        evaluations.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let domain = EvaluationDomain::<$field_ty>::new(domain_size as usize)
                        .ok_or_else(invalid_domain_error)?;
                    let evals = Evaluations::from_vec_and_domain(elems, domain);
                    let poly = evals.interpolate();
                    Ok(self.inner.commit(&poly, None).into())
                }

                #[napi]
                pub fn b_poly_commitment(&self, chals: Uint8Array) -> Result<$poly_comm_wrapper> {
                    let elements: Vec<$field_ty> = WasmFlatVector::<$wasm_field>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let coeffs = b_poly_coefficients(&elements);
                    let poly = DensePolynomial::<$field_ty>::from_coefficients_vec(coeffs);
                    Ok(self.inner.commit_non_hiding(&poly, 1).into())
                }

                #[napi]
                pub fn batch_accumulator_check(
                    &self,
                    commitments: WasmVector<$group_wrapper>,
                    chals: Uint8Array,
                ) -> Result<bool> {
                    let comms: Vec<$group_ty> = commitments.into_iter().map(Into::into).collect();
                    let chals: Vec<$field_ty> = WasmFlatVector::<$wasm_field>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    Ok(poly_commitment::utils::batch_dlog_accumulator_check(
                        &self.inner,
                        &comms,
                        &chals,
                    ))
                }

                #[napi]
                pub fn batch_accumulator_generate(
                    &self,
                    count: i32,
                    chals: Uint8Array,
                ) -> Result<WasmVector<$group_wrapper>> {
                    let chals: Vec<$field_ty> = WasmFlatVector::<$wasm_field>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let points = poly_commitment::utils::batch_dlog_accumulator_generate::<$group_ty>(
                        &self.inner,
                        count as usize,
                        &chals,
                    );
                    Ok(points.into_iter().map(Into::into).collect())
                }

                #[napi]
                pub fn h(&self) -> $group_wrapper {
                    self.inner.h.into()
                }
            }
        }
    };
}

impl_srs_module!(
    fp,
    mina_curves::pasta::Fp,
    WasmPastaFp,
    mina_curves::pasta::Vesta,
    WasmGVesta,
    WasmFpPolyComm,
    WasmFpSrs
);

impl_srs_module!(
    fq,
    mina_curves::pasta::Fq,
    WasmPastaFq,
    mina_curves::pasta::Pallas,
    WasmGPallas,
    WasmFqPolyComm,
    WasmFqSrs
);
