use crate::commitment::CommitmentCurve;

const MIN_SRS_FAST_PATH_POINTS: usize = 16_384;
const MIN_POLY_COMM_FAST_PATH_POINTS: usize = 4_096;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::{CommitmentCurve, MIN_POLY_COMM_FAST_PATH_POINTS, MIN_SRS_FAST_PATH_POINTS};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use js_sys::Uint8Array;
    use std::any::type_name;
    use std::time::Instant;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = o1jsMontgomeryProverMsmEnabled)]
        fn o1js_montgomery_prover_msm_enabled() -> bool;

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
            label: &str,
        ) -> Result<JsValue, JsValue>;
    }

    pub fn msm<G>(points: &[G], scalars: &[G::ScalarField]) -> Option<G>
    where
        G: CommitmentCurve,
        G::BaseField: CanonicalDeserialize + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize,
    {
        if points.len() < MIN_SRS_FAST_PATH_POINTS || points.len() != scalars.len() {
            return None;
        }
        msm_inner(points.iter(), scalars.iter(), points.len())
    }

    pub fn msm_refs<G>(points: &[&G], scalars: &[&G::ScalarField]) -> Option<G>
    where
        G: CommitmentCurve,
        G::BaseField: CanonicalDeserialize + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize,
    {
        if points.len() < MIN_POLY_COMM_FAST_PATH_POINTS || points.len() != scalars.len() {
            return None;
        }
        msm_inner(
            points.iter().copied(),
            scalars.iter().copied(),
            points.len(),
        )
    }

    pub fn msm_refs_batch<G>(batches: &[(&[&G], &[&G::ScalarField])], label: &str) -> Option<Vec<G>>
    where
        G: CommitmentCurve,
        G::BaseField: CanonicalDeserialize + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize,
    {
        if batches.is_empty()
            || batches.iter().any(|(points, scalars)| {
                points.len() < MIN_POLY_COMM_FAST_PATH_POINTS || points.len() != scalars.len()
            })
        {
            return None;
        }
        msm_batch_inner(
            batches.iter().map(|(points, scalars)| {
                (
                    points.iter().copied(),
                    scalars.iter().copied(),
                    points.len(),
                )
            }),
            label,
        )
    }

    pub fn msm_batch<G>(batches: &[(&[G], &[G::ScalarField])]) -> Option<Vec<G>>
    where
        G: CommitmentCurve,
        G::BaseField: CanonicalDeserialize + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize,
    {
        if batches.is_empty()
            || batches.iter().any(|(points, scalars)| {
                points.len() < MIN_SRS_FAST_PATH_POINTS || points.len() != scalars.len()
            })
        {
            return None;
        }
        msm_batch_inner(
            batches
                .iter()
                .map(|(points, scalars)| (points.iter(), scalars.iter(), points.len())),
            "ipa.commit_non_hiding.chunks",
        )
    }

    fn msm_inner<'a, G>(
        points: impl IntoIterator<Item = &'a G>,
        scalars: impl IntoIterator<Item = &'a G::ScalarField>,
        len: usize,
    ) -> Option<G>
    where
        G: CommitmentCurve + 'a,
        G::BaseField: CanonicalDeserialize + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize + 'a,
    {
        if !o1js_montgomery_prover_msm_enabled() {
            return None;
        }
        let curve = curve_name::<G>()?;

        let start = Instant::now();
        let result = (|| {
            let mut point_bytes = Vec::with_capacity(len * 64);
            let mut scalar_bytes = Vec::with_capacity(len * 32);

            for point in points {
                let (x, y) = point.to_coordinates()?;
                serialize_32(&x, &mut point_bytes)?;
                serialize_32(&y, &mut point_bytes)?;
            }
            for scalar in scalars {
                serialize_32(scalar, &mut scalar_bytes)?;
            }

            deserialize_result(o1js_montgomery_srs_msm(curve, &point_bytes, &scalar_bytes).ok()?)
        })();
        crate::msm_profiler::record_micros::<G>(
            "montgomery.single",
            len,
            start.elapsed().as_micros(),
        );
        result
    }

    fn msm_batch_inner<'a, G, PointIter, ScalarIter>(
        batches: impl IntoIterator<Item = (PointIter, ScalarIter, usize)>,
        label: &str,
    ) -> Option<Vec<G>>
    where
        G: CommitmentCurve + 'a,
        G::BaseField: CanonicalDeserialize + CanonicalSerialize,
        G::ScalarField: CanonicalSerialize + 'a,
        PointIter: IntoIterator<Item = &'a G>,
        ScalarIter: IntoIterator<Item = &'a G::ScalarField>,
    {
        if !o1js_montgomery_prover_msm_enabled() {
            return None;
        }
        let curve = curve_name::<G>()?;

        let start = Instant::now();
        let mut point_bytes = Vec::new();
        let mut scalar_bytes = Vec::new();
        let mut sizes = Vec::new();
        let mut total_len = 0usize;

        for (points, scalars, len) in batches {
            let len = u32::try_from(len).ok()?;
            sizes.push(len);
            total_len += len as usize;

            point_bytes.reserve(len as usize * 64);
            scalar_bytes.reserve(len as usize * 32);

            for point in points {
                let (x, y) = point.to_coordinates()?;
                serialize_32(&x, &mut point_bytes)?;
                serialize_32(&y, &mut point_bytes)?;
            }
            for scalar in scalars {
                serialize_32(scalar, &mut scalar_bytes)?;
            }
        }

        let result = deserialize_batch_result(
            o1js_montgomery_srs_msm_batch(curve, &point_bytes, &scalar_bytes, &sizes, label)
                .ok()?,
        );
        crate::msm_profiler::record_micros::<G>(
            profiler_label(label),
            total_len,
            start.elapsed().as_micros(),
        );
        result
    }

    fn deserialize_result<G>(result: JsValue) -> Option<G>
    where
        G: CommitmentCurve,
        G::BaseField: CanonicalDeserialize,
    {
        if result.is_undefined() || result.is_null() {
            return None;
        }
        let result = Uint8Array::new(&result).to_vec();
        if result.len() != 64 {
            return None;
        }

        let x = G::BaseField::deserialize_compressed(&mut &result[..32]).ok()?;
        let y = G::BaseField::deserialize_compressed(&mut &result[32..]).ok()?;
        Some(G::of_coordinates(x, y))
    }

    fn deserialize_batch_result<G>(result: JsValue) -> Option<Vec<G>>
    where
        G: CommitmentCurve,
        G::BaseField: CanonicalDeserialize,
    {
        if result.is_undefined() || result.is_null() {
            return None;
        }
        let result = Uint8Array::new(&result).to_vec();
        if result.len() % 64 != 0 {
            return None;
        }

        result
            .chunks_exact(64)
            .map(|chunk| {
                let x = G::BaseField::deserialize_compressed(&mut &chunk[..32]).ok()?;
                let y = G::BaseField::deserialize_compressed(&mut &chunk[32..]).ok()?;
                Some(G::of_coordinates(x, y))
            })
            .collect()
    }

    fn curve_name<G>() -> Option<&'static str> {
        let name = type_name::<G>();
        if name.contains("vesta") || name.contains("Vesta") {
            Some("vesta")
        } else if name.contains("pallas") || name.contains("Pallas") {
            Some("pallas")
        } else {
            None
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

    fn profiler_label(label: &str) -> &'static str {
        match label {
            "ipa.commit_non_hiding.chunks" => "montgomery.ipa.commit_non_hiding.chunks",
            "poly_comm.single" => "montgomery.poly_comm.single",
            "prover.witness" => "montgomery.prover.witness",
            "verifier_index.columns" => "montgomery.verifier_index.columns",
            _ => "montgomery.batch",
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::{msm, msm_batch, msm_refs, msm_refs_batch};

#[cfg(not(target_arch = "wasm32"))]
pub fn msm<G>(_points: &[G], _scalars: &[G::ScalarField]) -> Option<G>
where
    G: CommitmentCurve,
{
    None
}

#[cfg(not(target_arch = "wasm32"))]
pub fn msm_refs<G>(_points: &[&G], _scalars: &[&G::ScalarField]) -> Option<G>
where
    G: CommitmentCurve,
{
    None
}

#[cfg(not(target_arch = "wasm32"))]
pub fn msm_refs_batch<G>(_batches: &[(&[&G], &[&G::ScalarField])], _label: &str) -> Option<Vec<G>>
where
    G: CommitmentCurve,
{
    None
}

#[cfg(not(target_arch = "wasm32"))]
pub fn msm_batch<G>(_batches: &[(&[G], &[G::ScalarField])]) -> Option<Vec<G>>
where
    G: CommitmentCurve,
{
    None
}
