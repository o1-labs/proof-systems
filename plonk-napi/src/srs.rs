use crate::vector::NapiVector;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations};
use core::ops::Deref;
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

macro_rules! impl_srs {
    (
        $name:ident,
        $NapiF:ty,
        $NapiG:ty,
        $F:ty,
        $G:ty,
        $NapiPolyComm:ty,
    ) => {
        paste! {

            #[napi(js_name = [<"Wasm" $name:camel "Srs">])]
            #[derive(Clone)]
            pub struct [<Napi $name:camel Srs>] (
                 #[napi(skip)] pub Arc<SRS<$G>>
            );

            impl Deref for [<Napi $name:camel Srs>] {
                type Target = Arc<SRS<$G>>;

                fn deref(&self) -> &Self::Target { &self.0 }
            }

            impl From<Arc<SRS<$G>>> for [<Napi $name:camel Srs>] {
                fn from(x: Arc<SRS<$G>>) -> Self {
                    [<Napi $name:camel Srs>](x)
                }
            }

            impl From<&Arc<SRS<$G>>> for [<Napi $name:camel Srs>] {
                fn from(x: &Arc<SRS<$G>>) -> Self {
                    [<Napi $name:camel Srs>](x.clone())
                }
            }

            impl From<[<Napi $name:camel Srs>]> for Arc<SRS<$G>> {
                fn from(x: [<Napi $name:camel Srs>]) -> Self {
                    x.0
                }
            }

            impl From<&[<Napi $name:camel Srs>]> for Arc<SRS<$G>> {
                fn from(x: &[<Napi $name:camel Srs>]) -> Self {
                    x.0.clone()
                }
            }

            impl<'a> From<&'a [<Napi $name:camel Srs>]> for &'a Arc<SRS<$G>> {
                fn from(x: &'a [<Napi $name:camel Srs>]) -> Self {
                    &x.0
                }
            }

            fn invalid_domain_error() -> Error {
                Error::new(Status::InvalidArg, "invalid domain size")
            }

            fn map_error(context: &str, err: impl std::fmt::Display) -> Error {
                Error::new(Status::GenericFailure, format!("{}: {}", context, err))
            }

            #[napi]
            impl [<Napi $name:camel Srs>] {

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
                    let srs: SRS<$G> = rmp_serde::from_slice(bytes.as_ref())
                        .map_err(|e| map_error("srs_deserialize", e))?;
                    Ok(Arc::new(srs).into())
                }

                #[napi(factory, js_name = [<"caml_" $name:snake "_srs_create">])]
                pub fn [<caml_ $name:snake _srs_create>](depth: i32) -> Result<Self> {
                    println!("Creating SRS with napi");
                    Ok(Arc::new(SRS::<$G>::create(depth as usize)).into())
                }

                #[napi(factory, js_name = [<"caml_" $name:snake "_srs_create_parallel">])]
                pub fn [<caml_ $name:snake _srs_create_parallel>](depth: i32) -> Result<Self> {
                    println!("Creating SRS in parallel with napi");
                    Ok(Arc::new(SRS::<$G>::create_parallel(
                        depth as usize,
                    )).into())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_add_lagrange_basis">])]
                pub fn [<caml_ $name:snake _srs_add_lagrange_basis>](srs: &[<Napi $name:camel Srs>], log2_size: i32) -> Result<()> {
                    println!("Adding lagrange basis with napi");
                    let size = 1usize << (log2_size as usize);
                    let domain = EvaluationDomain::<$F>::new(size).ok_or_else(invalid_domain_error)?;
                    srs.get_lagrange_basis(domain);
                    Ok(())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_write">])]
                pub fn [<caml_ $name:snake _srs_write>](append: Option<bool>, srs: &[<Napi $name:camel Srs>], path: String) -> Result<()> {
                    println!("Writing SRS to file with napi");
                    let function_name = format!("caml_{0}_srs_write", stringify!($name).to_lowercase());
                    let file = OpenOptions::new()
                        .append(append.unwrap_or(true))
                        .open(&path)
                        .map_err(|err| map_error(&function_name, err))?;
                    let file = BufWriter::new(file);
                    srs.0.serialize(&mut rmp_serde::Serializer::new(file))
                        .map_err(|err| map_error(&function_name, err))
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_read">])]
                pub fn [<caml_ $name:snake _srs_read>](offset: Option<i32>, path: String) -> Result<Option<Self>> {
                    println!("Reading SRS from file with napi");
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

                    match SRS::<$G>::deserialize(&mut rmp_serde::Deserializer::new(reader)) {
                        Ok(srs) => Ok(Some(Arc::new(srs).into())),
                        Err(_) => Ok(None),
                    }
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_get">])]
                pub fn [<caml_ $name:snake _srs_get>](srs: &[<Napi $name:camel Srs>]) -> Vec<$NapiG> {
                    println!("Getting SRS with napi");
                    let mut h_and_gs: Vec<$NapiG> = vec![srs.0.h.into()];
                    h_and_gs.extend(srs.0.g.iter().cloned().map(Into::into));
                    h_and_gs
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_set">])]
                pub fn [<caml_ $name:snake _srs_set>](h_and_gs: Vec<$NapiG>) -> Result<Self> {
                    println!("Setting SRS with napi");
                    let mut h_and_gs: Vec<$G> = h_and_gs.into_iter().map(Into::into).collect();
                    if h_and_gs.is_empty() {
                        return Err(Error::new(
                            Status::InvalidArg,
                            "expected at least one element for SRS",
                        ));
                    }
                    let h = h_and_gs.remove(0);
                    let g = h_and_gs;
                    let srs = SRS::<$G> { h, g, lagrange_bases: HashMapCache::new() };
                    Ok(Arc::new(srs).into())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_maybe_lagrange_commitment">])]
                pub fn [<caml_ $name:snake _srs_maybe_lagrange_commitment>](
                    srs: &[<Napi $name:camel Srs>],
                    domain_size: i32,
                    i: i32,
                ) -> Option<$NapiPolyComm> {
                    println!("Getting maybe lagrange commitment with napi");
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

                #[napi(js_name = [<"caml_" $name:snake "_srs_set_lagrange_basis">])]
                pub fn [<caml_ $name:snake _srs_set_lagrange_basis>](srs: &[<Napi $name:camel Srs>],
                    domain_size: i32,
                    input_bases: NapiVector<$NapiPolyComm>,
                ) {
                    println!("Setting lagrange basis with napi");
                    srs.0.lagrange_bases
                        .get_or_generate(domain_size as usize, || { input_bases.into_iter().map(Into::into).collect()});
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_get_lagrange_basis">])]
                pub fn [<caml_ $name:snake _srs_get_lagrange_basis>](srs: &[<Napi $name:camel Srs>],
                    domain_size: i32,
                ) -> Result<NapiVector<$NapiPolyComm>> {
                    println!("Getting lagrange basis with napi");
                    let domain = EvaluationDomain::<$F>::new(domain_size as usize)
                        .ok_or_else(invalid_domain_error)?;
                    let basis = srs.0.get_lagrange_basis(domain);
                    Ok(basis.iter().cloned().map(Into::into).collect())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_to_bytes">])]
                pub fn [<caml_ $name:snake _srs_to_bytes>](srs: &[<Napi $name:camel Srs>]) -> Result<Uint8Array> {
                    srs.serialize()
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_from_bytes">])]
                pub fn [<caml_ $name:snake _srs_from_bytes>](bytes: Uint8Array) -> Result<Self> {
                    Self::deserialize(bytes)
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_commit_evaluations">])]
                pub fn [<caml_ $name:snake _srs_commit_evaluations>](srs: &[<Napi $name:camel Srs>],
                    domain_size: i32,
                    evals: Uint8Array,
                ) -> Result<$NapiPolyComm> {
                    println!("Committing evaluations with napi");
                    let elems: Vec<$F> = WasmFlatVector::<$NapiF>::from_bytes(
                        evals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let x_domain = EvaluationDomain::<$F>::new(domain_size as usize)
                        .ok_or_else(invalid_domain_error)?;
                    let evals = elems.into_iter().map(Into::into).collect();
                    let p = Evaluations::<$F>::from_vec_and_domain(evals, x_domain).interpolate();
                    Ok(srs.commit_non_hiding(&p, 1).into())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_b_poly_commitment">])]
                pub fn [<caml_ $name:snake _srs_b_poly_commitment>](srs: &[<Napi $name:camel Srs>], chals: Uint8Array) -> Result<$NapiPolyComm> {
                    println!("Computing b poly commitment with napi");
                    let elements: Vec<$F> = WasmFlatVector::<$NapiF>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let coeffs = b_poly_coefficients(&elements);
                    let p = DensePolynomial::<$F>::from_coefficients_vec(coeffs);
                    Ok(srs.commit_non_hiding(&p, 1).into())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_batch_accumulator_check">])]
                pub fn [<caml_ $name:snake _srs_batch_accumulator_check>](
                    srs: &[<Napi $name:camel Srs>],
                    comms: NapiVector<$NapiG>,
                    chals: Uint8Array,
                ) -> Result<bool> {
                    println!("Performing batch accumulator check with napi");
                    let comms: Vec<$G> = comms.into_iter().map(Into::into).collect();
                    let chals: Vec<$F> = WasmFlatVector::<$NapiF>::from_bytes(
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

                #[napi(js_name = [<"caml_" $name:snake "_srs_batch_accumulator_generate">])]
                pub fn [<caml_ $name:snake _srs_batch_accumulator_generate>](
                    srs: &[<Napi $name:camel Srs>],
                    comms: i32,
                    chals: Uint8Array,
                ) -> Result<NapiVector<$NapiG>> {
                    println!("Generating batch accumulator with napi");
                    let chals: Vec<$F> = WasmFlatVector::<$NapiF>::from_bytes(
                        chals.as_ref().to_vec(),
                    )
                    .into_iter()
                    .map(Into::into)
                    .collect();
                    let points = poly_commitment::utils::batch_dlog_accumulator_generate::<$G>(
                        &srs,
                        comms as usize,
                        &chals,
                    );
                    Ok(points.into_iter().map(Into::into).collect())
                }

                #[napi(js_name = [<"caml_" $name:snake "_srs_get_h">])]
                pub fn h(srs: &[<Napi $name:camel Srs>]) -> $NapiG {
                    println!("Getting h point with napi");
                    srs.h.into()
                }
            }
        }
    }
}

#[napi]
pub fn caml_fp_srs_to_bytes(srs: &fp::NapiFpSrs) -> Result<Uint8Array> {
    srs.serialize()
}

#[napi]
pub fn caml_fp_srs_from_bytes(bytes: Uint8Array) -> Result<fp::NapiFpSrs> {
    fp::NapiFpSrs::deserialize(bytes)
}

#[napi(js_name = "caml_fp_srs_from_bytes_external")]
pub fn caml_fp_srs_from_bytes_external(bytes: Uint8Array) -> External<fp::NapiFpSrs> {
    let srs = caml_fp_srs_from_bytes(bytes).unwrap();
    External::new(srs)
}

#[napi]
pub fn caml_fq_srs_from_bytes(bytes: Uint8Array) -> Result<fq::NapiFqSrs> {
    fq::NapiFqSrs::deserialize(bytes)
}

#[napi]
pub fn caml_fq_srs_from_bytes_external(bytes: Uint8Array) -> External<fq::NapiFqSrs> {
    let srs = caml_fq_srs_from_bytes(bytes).unwrap();
    External::new(srs)
}

pub mod fp {
    use super::*;
    use crate::{
        poly_comm::vesta::NapiFpPolyComm,
        wrappers::{field::NapiPastaFp, group::NapiGVesta},
    };
    impl_srs!(
        fp,                        // field name
        NapiPastaFp,               // Napi field wrapper
        NapiGVesta,                // Napi group wrapper
        mina_curves::pasta::Fp,    // Actual Kimchi field
        mina_curves::pasta::Vesta, // Actual kimchi group
        NapiFpPolyComm,            // Napi poly commitment type
    );
}

pub mod fq {
    use super::*;
    use crate::{
        poly_comm::pallas::NapiFqPolyComm,
        wrappers::{field::NapiPastaFq, group::NapiGPallas},
    };
    impl_srs!(
        fq,                         // Field name
        NapiPastaFq,                // Napi field wrapper
        NapiGPallas,                // Napi group wrapper
        mina_curves::pasta::Fq,     // Actual Kimchi field
        mina_curves::pasta::Pallas, // Actual kimchi group
        NapiFqPolyComm,             // Napi poly commitment type
    );
}
