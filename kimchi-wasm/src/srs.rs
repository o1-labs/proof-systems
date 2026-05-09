use crate::wasm_vector::WasmVector;
use ark_ec::AffineRepr;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::ops::Deref;
use js_sys::Uint8Array;
use paste::paste;
use poly_commitment::{
    commitment::b_poly_coefficients, hash_map_cache::HashMapCache, ipa::SRS, PolyComm, SRS as ISRS,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Cursor, Seek, SeekFrom::Start},
    sync::Arc,
};
use wasm_bindgen::prelude::*;
use wasm_types::FlatVector as WasmFlatVector;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = o1jsMontgomerySrsMsmEnabled)]
    fn o1js_montgomery_srs_msm_enabled() -> bool;

    #[wasm_bindgen(catch, js_name = o1jsMontgomerySrsMsm)]
    fn o1js_montgomery_srs_msm(
        curve: &str,
        point_bytes: &[u8],
        scalar_bytes: &[u8],
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_name = o1jsMontgomerySrsMsmBatch)]
    fn o1js_montgomery_srs_msm_batch(
        curve: &str,
        point_bytes: &[u8],
        scalar_bytes: &[u8],
        sizes: &[u32],
    ) -> Result<JsValue, JsValue>;
}

macro_rules! impl_srs {
    ($name: ident,
     $WasmF: ty,
     $WasmG: ty,
     $F: ty,
     $G: ty,
     $WasmPolyComm: ty,
     $field_name: ident,
     $montgomery_curve: expr) => {
        paste! {
            #[wasm_bindgen]
            #[derive(Clone)]
            pub struct [<Wasm $field_name:camel Srs>](
                #[wasm_bindgen(skip)]
                pub Arc<SRS<$G>>);

            #[wasm_bindgen]
            impl [<Wasm $field_name:camel Srs>] {
                #[wasm_bindgen(js_name = "serialize")]
                pub fn serialize(&self) -> Result<Vec<u8>, JsValue> {
                    let mut buffer = Vec::new();
                    self.0
                        .serialize(&mut rmp_serde::Serializer::new(&mut buffer))
                        .map_err(|e| JsValue::from_str(&format!("srs serialize failed: {e}")))?;
                    Ok(buffer)
                }

                #[wasm_bindgen(js_name = "deserialize")]
                pub fn deserialize(bytes: &[u8]) -> Result<[<Wasm $field_name:camel Srs>], JsValue> {
                    let srs = SRS::<$G>::deserialize(&mut rmp_serde::Deserializer::new(Cursor::new(bytes)))
                        .map_err(|e| JsValue::from_str(&format!("srs deserialize failed: {e}")))?;
                    Ok(Arc::new(srs).into())
                }
            }

            impl Deref for [<Wasm $field_name:camel Srs>] {
                type Target = Arc<SRS<$G>>;

                fn deref(&self) -> &Self::Target { &self.0 }
            }

            impl From<Arc<SRS<$G>>> for [<Wasm $field_name:camel Srs>] {
                fn from(x: Arc<SRS<$G>>) -> Self {
                    [<Wasm $field_name:camel Srs>](x)
                }
            }

            impl From<&Arc<SRS<$G>>> for [<Wasm $field_name:camel Srs>] {
                fn from(x: &Arc<SRS<$G>>) -> Self {
                    [<Wasm $field_name:camel Srs>](x.clone())
                }
            }

            impl From<[<Wasm $field_name:camel Srs>]> for Arc<SRS<$G>> {
                fn from(x: [<Wasm $field_name:camel Srs>]) -> Self {
                    x.0
                }
            }

            impl From<&[<Wasm $field_name:camel Srs>]> for Arc<SRS<$G>> {
                fn from(x: &[<Wasm $field_name:camel Srs>]) -> Self {
                    x.0.clone()
                }
            }

            impl<'a> From<&'a [<Wasm $field_name:camel Srs>]> for &'a Arc<SRS<$G>> {
                fn from(x: &'a [<Wasm $field_name:camel Srs>]) -> Self {
                    &x.0
                }
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _create>](depth: i32) -> [<Wasm $field_name:camel Srs>] {
                Arc::new(SRS::create(depth as usize)).into()
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _add_lagrange_basis>](
                srs: &[<Wasm $field_name:camel Srs>],
                log2_size: i32,
            ) {
                crate::rayon::run_in_pool(|| {
                    let domain = EvaluationDomain::<$F>::new(1 << (log2_size as usize)).expect("invalid domain size");
                    srs.get_lagrange_basis(domain);
                });
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _write>](
                append: Option<bool>,
                srs: &[<Wasm $field_name:camel Srs>],
                path: String,
            ) -> Result<(), JsValue> {
                let file = OpenOptions::new()
                    .append(append.unwrap_or(true))
                    .open(path)
                    .map_err(|err| {
                        JsValue::from_str(format!("caml_pasta_fp_urs_write: {}", err).as_str())
                    })?;
                let file = BufWriter::new(file);

                srs.0.serialize(&mut rmp_serde::Serializer::new(file))
                .map_err(|e| JsValue::from_str(format!("caml_pasta_fp_urs_write: {}", e).as_str()))
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _read>](
                offset: Option<i32>,
                path: String,
            ) -> Result<Option<[<Wasm $field_name:camel Srs>]>, JsValue> {
                let file = File::open(path).map_err(|err| {
                    JsValue::from_str(format!("caml_pasta_fp_urs_read: {}", err).as_str())
                })?;
                let mut reader = BufReader::new(file);

                if let Some(offset) = offset {
                    reader.seek(Start(offset as u64)).map_err(|err| {
                        JsValue::from_str(format!("caml_pasta_fp_urs_read: {}", err).as_str())
                    })?;
                }

                // TODO: shouldn't we just error instead of returning None?
                let srs = match SRS::<$G>::deserialize(&mut rmp_serde::Deserializer::new(reader)) {
                    Ok(srs) => srs,
                    Err(_) => return Ok(None),
                };

                Ok(Some(Arc::new(srs).into()))
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _lagrange_commitments_whole_domain_ptr>](
                srs: &[<Wasm $field_name:camel Srs>],
                domain_size: i32,
            ) -> *mut WasmVector<$WasmPolyComm> {
                // this is the best workaround we have, for now
                // returns a pointer to the commitment
                // later, we read the commitment from the pointer
                let comm = srs
                    .get_lagrange_basis_from_domain_size(domain_size as usize)
                    .clone()
                    .into_iter()
                    .map(|x| x.into())
                    .collect();
                let boxed_comm = Box::<WasmVector<WasmPolyComm>>::new(comm);
                Box::into_raw(boxed_comm)
            }

            /// Reads the lagrange commitments from a raw pointer.
            ///
            /// # Safety
            ///
            /// This function is unsafe because it might dereference a
            /// raw pointer.
            #[wasm_bindgen]
            pub unsafe fn [<$name:snake _lagrange_commitments_whole_domain_read_from_ptr>](
                ptr: *mut WasmVector<$WasmPolyComm>,
            ) -> WasmVector<$WasmPolyComm> {
                // read the commitment at the pointers address, hack for the web
                // worker implementation (see o1js web worker impl for details)
                let b = unsafe { Box::from_raw(ptr) };
                b.as_ref().clone()
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _lagrange_commitment>](
                srs: &[<Wasm $field_name:camel Srs>],
                domain_size: i32,
                i: i32,
            ) -> Result<$WasmPolyComm, JsValue> {
                let x_domain = EvaluationDomain::<$F>::new(domain_size as usize).ok_or_else(|| {
                    JsValue::from_str("caml_pasta_fp_urs_lagrange_commitment")
                })?;
                let basis =
                    crate::rayon::run_in_pool(|| {
                        srs.get_lagrange_basis(x_domain)
                    });

                Ok(basis[i as usize].clone().into())
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _commit_evaluations>](
                srs: &[<Wasm $field_name:camel Srs>],
                domain_size: i32,
                evals: WasmFlatVector<$WasmF>,
            ) -> Result<$WasmPolyComm, JsValue> {
                let x_domain = EvaluationDomain::<$F>::new(domain_size as usize).ok_or_else(|| {
                    JsValue::from_str("caml_pasta_fp_urs_commit_evaluations")
                })?;

                let evals = evals.into_iter().map(Into::into).collect();
                let p = Evaluations::<$F>::from_vec_and_domain(evals, x_domain).interpolate();

                if let Some(commitment) =
                    [<$name:snake _commit_non_hiding_montgomery>](&srs.0, &p.coeffs)
                {
                    return Ok(commitment.into());
                }

                Ok(srs.commit_non_hiding(&p, 1).into())
            }

            fn [<$name:snake _commit_non_hiding_montgomery>](
                srs: &Arc<SRS<$G>>,
                coeffs: &[$F],
            ) -> Option<PolyComm<$G>> {
                if !o1js_montgomery_srs_msm_enabled() {
                    return None;
                }
                if coeffs.is_empty() || coeffs.len() > srs.g.len() {
                    return None;
                }

                let mut point_bytes = Vec::with_capacity(coeffs.len() * 64);
                let mut scalar_bytes = Vec::with_capacity(coeffs.len() * 32);

                for point in &srs.g[..coeffs.len()] {
                    if point.is_zero() {
                        return None;
                    }
                    serialize_32(&point.x, &mut point_bytes)?;
                    serialize_32(&point.y, &mut point_bytes)?;
                }
                for scalar in coeffs {
                    serialize_32(scalar, &mut scalar_bytes)?;
                }

                #[allow(clippy::cast_possible_truncation)]
                let sizes = [coeffs.len() as u32];
                let result = o1js_montgomery_srs_msm_batch(
                    $montgomery_curve,
                    &point_bytes,
                    &scalar_bytes,
                    &sizes,
                )
                .ok()
                .and_then(|result| {
                    if result.is_undefined() || result.is_null() {
                        None
                    } else {
                        let bytes = Uint8Array::new(&result).to_vec();
                        (bytes.len() == 64).then_some(bytes)
                    }
                })
                .or_else(|| {
                    let result = o1js_montgomery_srs_msm(
                        $montgomery_curve,
                        &point_bytes,
                        &scalar_bytes,
                    )
                    .ok()?;
                    if result.is_undefined() || result.is_null() {
                        None
                    } else {
                        let bytes = Uint8Array::new(&result).to_vec();
                        (bytes.len() == 64).then_some(bytes)
                    }
                })?;

                let x =
                    <$G as AffineRepr>::BaseField::deserialize_compressed(&mut &result[..32]).ok()?;
                let y =
                    <$G as AffineRepr>::BaseField::deserialize_compressed(&mut &result[32..]).ok()?;
                let point: $G = $G {
                    x,
                    y,
                    infinity: false,
                };
                Some(PolyComm::<$G>::new(vec![point]))
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _b_poly_commitment>](
                srs: &[<Wasm $field_name:camel Srs>],
                chals: WasmFlatVector<$WasmF>,
            ) -> Result<$WasmPolyComm, JsValue> {
                let result = crate::rayon::run_in_pool(|| {
                    let chals: Vec<$F> = chals.into_iter().map(Into::into).collect();
                    let coeffs = b_poly_coefficients(&chals);
                    let p = DensePolynomial::<$F>::from_coefficients_vec(coeffs);
                    srs.commit_non_hiding(&p, 1)
                });
                Ok(result.into())
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _batch_accumulator_check>](
                srs: &[<Wasm $field_name:camel Srs>],
                comms: WasmVector<$WasmG>,
                chals: WasmFlatVector<$WasmF>,
            ) -> bool {
                crate::rayon::run_in_pool(|| {
                    let comms: Vec<_> = comms.into_iter().map(Into::into).collect();
                    let chals: Vec<_> = chals.into_iter().map(Into::into).collect();
                    poly_commitment::utils::batch_dlog_accumulator_check(&srs, &comms, &chals)
                })
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _batch_accumulator_generate>](
                srs: &[<Wasm $field_name:camel Srs>],
                comms: i32,
                chals: WasmFlatVector<$WasmF>,
            ) -> WasmVector<$WasmG> {
                let chals_vec: Vec<_> = chals.into_iter().map(From::from).collect();
                poly_commitment::utils::batch_dlog_accumulator_generate::<$G>(
                    &srs,
                    comms as usize,
                    &chals_vec,
                ).into_iter().map(Into::into).collect()
            }

            #[wasm_bindgen]
            pub fn [<$name:snake _h>](srs: &[<Wasm $field_name:camel Srs>]) -> $WasmG {
                srs.h.into()
            }
        }
    }
}

fn serialize_32<T: CanonicalSerialize>(value: &T, out: &mut Vec<u8>) -> Option<()> {
    let offset = out.len();
    value.serialize_compressed(&mut *out).ok()?;
    if out.len() == offset + 32 {
        Some(())
    } else {
        None
    }
}

//
// Fp
//

pub mod fp {
    use super::*;
    use crate::poly_comm::vesta::WasmFpPolyComm as WasmPolyComm;
    use arkworks::{WasmGVesta as WasmG, WasmPastaFp};
    use mina_curves::pasta::{Fp, Vesta as G};

    impl_srs!(
        caml_fp_srs,
        WasmPastaFp,
        WasmG,
        Fp,
        G,
        WasmPolyComm,
        Fp,
        "vesta"
    );
    #[wasm_bindgen]
    pub fn caml_fp_srs_create_parallel(depth: i32) -> WasmFpSrs {
        crate::rayon::run_in_pool(|| Arc::new(SRS::<G>::create_parallel(depth as usize)).into())
    }

    // return the cloned srs in a form that we can store on the js side
    #[wasm_bindgen]
    pub fn caml_fp_srs_get(srs: &WasmFpSrs) -> WasmVector<WasmG> {
        // return a vector which consists of h, then all the gs
        let mut h_and_gs: Vec<WasmG> = vec![srs.0.h.into()];
        h_and_gs.extend(srs.0.g.iter().map(|x: &G| WasmG::from(*x)));
        h_and_gs.into()
    }

    // set the srs from a vector of h and gs
    #[wasm_bindgen]
    pub fn caml_fp_srs_set(h_and_gs: WasmVector<WasmG>) -> WasmFpSrs {
        // return a vector which consists of h, then all the gs
        let mut h_and_gs: Vec<G> = h_and_gs.into_iter().map(|x| x.into()).collect();
        let h = h_and_gs.remove(0);
        let g = h_and_gs;
        let srs = SRS::<G> {
            h,
            g,
            lagrange_bases: HashMapCache::new(),
        };
        Arc::new(srs).into()
    }

    // maybe get lagrange commitment
    #[wasm_bindgen]
    pub fn caml_fp_srs_maybe_lagrange_commitment(
        srs: &WasmFpSrs,
        domain_size: i32,
        i: i32,
    ) -> Option<WasmPolyComm> {
        if !(srs.0.lagrange_bases.contains_key(&(domain_size as usize))) {
            return None;
        }
        let basis = srs.get_lagrange_basis_from_domain_size(domain_size as usize);
        Some(basis[i as usize].clone().into())
    }

    // set entire lagrange basis from input
    #[wasm_bindgen]
    pub fn caml_fp_srs_set_lagrange_basis(
        srs: &WasmFpSrs,
        domain_size: i32,
        input_bases: WasmVector<WasmPolyComm>,
    ) {
        srs.lagrange_bases
            .get_or_generate(domain_size as usize, || {
                input_bases.into_iter().map(Into::into).collect()
            });
    }

    // compute & add lagrange basis internally, return the entire basis
    #[wasm_bindgen]
    pub fn caml_fp_srs_get_lagrange_basis(
        srs: &WasmFpSrs,
        domain_size: i32,
    ) -> WasmVector<WasmPolyComm> {
        // compute lagrange basis
        let basis = crate::rayon::run_in_pool(|| {
            let domain =
                EvaluationDomain::<Fp>::new(domain_size as usize).expect("invalid domain size");
            srs.get_lagrange_basis(domain)
        });
        basis.iter().map(Into::into).collect()
    }
}

pub mod fq {
    use super::*;
    use crate::poly_comm::pallas::WasmFqPolyComm as WasmPolyComm;
    use arkworks::{WasmGPallas as WasmG, WasmPastaFq};
    use mina_curves::pasta::{Fq, Pallas as G};

    impl_srs!(
        caml_fq_srs,
        WasmPastaFq,
        WasmG,
        Fq,
        G,
        WasmPolyComm,
        Fq,
        "pallas"
    );

    #[wasm_bindgen]
    pub fn caml_fq_srs_create_parallel(depth: i32) -> WasmFqSrs {
        crate::rayon::run_in_pool(|| Arc::new(SRS::<G>::create_parallel(depth as usize)).into())
    }

    // return the cloned srs in a form that we can store on the js side
    #[wasm_bindgen]
    pub fn caml_fq_srs_get(srs: &WasmFqSrs) -> WasmVector<WasmG> {
        // return a vector which consists of h, then all the gs
        let mut h_and_gs: Vec<WasmG> = vec![srs.0.h.into()];
        h_and_gs.extend(srs.0.g.iter().map(|x: &G| WasmG::from(*x)));
        h_and_gs.into()
    }

    // set the srs from a vector of h and gs
    #[wasm_bindgen]
    pub fn caml_fq_srs_set(h_and_gs: WasmVector<WasmG>) -> WasmFqSrs {
        // return a vector which consists of h, then all the gs
        let mut h_and_gs: Vec<G> = h_and_gs.into_iter().map(|x| x.into()).collect();
        let h = h_and_gs.remove(0);
        let g = h_and_gs;
        let srs = SRS::<G> {
            h,
            g,
            lagrange_bases: HashMapCache::new(),
        };
        Arc::new(srs).into()
    }

    // maybe get lagrange commitment
    #[wasm_bindgen]
    pub fn caml_fq_srs_maybe_lagrange_commitment(
        srs: &WasmFqSrs,
        domain_size: i32,
        i: i32,
    ) -> Option<WasmPolyComm> {
        if !(srs.0.lagrange_bases.contains_key(&(domain_size as usize))) {
            return None;
        }
        let basis = srs.get_lagrange_basis_from_domain_size(domain_size as usize);
        Some(basis[i as usize].clone().into())
    }

    // set entire lagrange basis from input
    #[wasm_bindgen]
    pub fn caml_fq_srs_set_lagrange_basis(
        srs: &WasmFqSrs,
        domain_size: i32,
        input_bases: WasmVector<WasmPolyComm>,
    ) {
        srs.lagrange_bases
            .get_or_generate(domain_size as usize, || {
                input_bases.into_iter().map(Into::into).collect()
            });
    }

    // compute & add lagrange basis internally, return the entire basis
    #[wasm_bindgen]
    pub fn caml_fq_srs_get_lagrange_basis(
        srs: &WasmFqSrs,
        domain_size: i32,
    ) -> WasmVector<WasmPolyComm> {
        // compute lagrange basis
        let basis = crate::rayon::run_in_pool(|| {
            let domain =
                EvaluationDomain::<Fq>::new(domain_size as usize).expect("invalid domain size");
            srs.get_lagrange_basis(domain)
        });
        basis.iter().map(Into::into).collect()
    }
}
