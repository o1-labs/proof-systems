use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use kimchi::{
    circuits::{
        constraints::{ColumnEvaluations, ConstraintSystem, FeatureFlags},
        domains::EvaluationDomains,
        gate::CircuitGate,
        lookup::index::{LookupConstraintSystem, LookupError},
        wires::PERMUTS,
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use o1_utils::lazy_cache::LazyCache;
use poly_commitment::ipa::OpeningProof;
use poly_commitment::OpenProof;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use std::sync::Arc;
use wasm_bindgen::JsError;

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(deserialize = ""), bound(serialize = ""))]
struct LegacyConstraintSystem<F: PrimeField> {
    public: usize,
    prev_challenges: usize,
    #[serde(bound = "EvaluationDomains<F>: Serialize + DeserializeOwned")]
    domain: EvaluationDomains<F>,
    #[serde(bound = "CircuitGate<F>: Serialize + DeserializeOwned")]
    gates: Arc<Vec<CircuitGate<F>>>,
    zk_rows: u64,
    feature_flags: FeatureFlags,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    sid: Vec<F>,
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    shift: [F; PERMUTS],
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    endo: F,
    #[serde(bound = "LookupConstraintSystem<F>: Serialize + DeserializeOwned")]
    lookup_constraint_system:
        Arc<LazyCache<Result<Option<LookupConstraintSystem<F>>, LookupError>>>,
    disable_gates_checks: bool,
}

impl<F> LegacyConstraintSystem<F>
where
    F: PrimeField,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    fn into_modern(self) -> Result<ConstraintSystem<F>, String> {
        let mut value = serde_json::to_value(self).map_err(|err| err.to_string())?;
        let map = value
            .as_object_mut()
            .ok_or_else(|| "legacy constraint system did not serialize as a map".to_string())?;
        map.entry("lazy_mode".to_owned())
            .or_insert(Value::Bool(false));

        serde_json::from_value(value).map_err(|err| err.to_string())
    }
}

#[serde_as]
#[derive(Deserialize)]
#[serde(bound(deserialize = ""))]
struct LegacyProverIndex<F: PrimeField, C: AffineRepr>
where
    C::ScalarField: PrimeField,
{
    cs: LegacyConstraintSystem<F>,
    max_poly_size: usize,
    column_evaluations: Arc<LazyCache<ColumnEvaluations<F>>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    verifier_index_digest: Option<C::BaseField>,
}

impl<F, C> LegacyProverIndex<F, C>
where
    F: PrimeField,
    C: AffineRepr<ScalarField = F> + KimchiCurve<ScalarField = F>,
    C::BaseField: PrimeField,
    <OpeningProof<C> as OpenProof<C>>::SRS: Default,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    fn upgrade(self) -> Result<ProverIndex<C, OpeningProof<C>>, String> {
        let cs = Arc::new(self.cs.into_modern()?);
        Ok(ProverIndex {
            cs,
            linearization: Default::default(),
            powers_of_alpha: Default::default(),
            srs: Default::default(),
            max_poly_size: self.max_poly_size,
            column_evaluations: self.column_evaluations,
            verifier_index: None,
            verifier_index_digest: self.verifier_index_digest,
        })
    }
}

pub(crate) fn decode_with_legacy<F, C>(
    bytes: &[u8],
    context: &str,
) -> Result<ProverIndex<C, OpeningProof<C>>, JsError>
where
    F: PrimeField,
    C: AffineRepr<ScalarField = F> + KimchiCurve<ScalarField = F>,
    C::BaseField: PrimeField,
    OpeningProof<C>: OpenProof<C>,
    <OpeningProof<C> as OpenProof<C>>::SRS: Default,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    let mut primary = rmp_serde::Deserializer::new(bytes);
    match ProverIndex::<C, OpeningProof<C>>::deserialize(&mut primary) {
        Ok(index) => Ok(index),
        Err(primary_err) => {
            let mut fallback = rmp_serde::Deserializer::new(bytes);
            let legacy =
                LegacyProverIndex::<F, C>::deserialize(&mut fallback).map_err(|legacy_err| {
                    JsError::new(&format!(
                        "{context}: {primary_err}; legacy decode failed: {legacy_err}"
                    ))
                })?;
            legacy
                .upgrade()
                .map_err(|err| JsError::new(&format!("{context}: {err}")))
        }
    }
}
