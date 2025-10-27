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
use poly_commitment::OpenProof;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;
use wasm_bindgen::JsError;

type IpaOpeningProof<C> = poly_commitment::ipa::OpeningProof<C>;

#[serde_as]
#[derive(Clone, Deserialize, Debug)]
#[serde(bound(deserialize = ""))]
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
        let serializable: ConstraintSystemWithLazy<F> = self.into();
        let mut buffer = Vec::new();
        serializable
            .serialize(&mut rmp_serde::Serializer::new(&mut buffer).with_struct_map())
            .map_err(|e| e.to_string())?;

        let mut deserializer = rmp_serde::Deserializer::new(&buffer[..]);
        ConstraintSystem::<F>::deserialize(&mut deserializer).map_err(|e| e.to_string())
    }
}

#[serde_as]
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
struct ConstraintSystemWithLazy<F: PrimeField> {
    public: usize,
    prev_challenges: usize,
    #[serde(bound(serialize = "EvaluationDomains<F>: Serialize"))]
    domain: EvaluationDomains<F>,
    #[serde(bound(serialize = "CircuitGate<F>: Serialize"))]
    gates: Arc<Vec<CircuitGate<F>>>,
    zk_rows: u64,
    feature_flags: FeatureFlags,
    lazy_mode: bool,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    sid: Vec<F>,
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    shift: [F; PERMUTS],
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    endo: F,
    #[serde(bound(serialize = "LookupConstraintSystem<F>: Serialize"))]
    lookup_constraint_system:
        Arc<LazyCache<Result<Option<LookupConstraintSystem<F>>, LookupError>>>,
    disable_gates_checks: bool,
}

impl<F> From<LegacyConstraintSystem<F>> for ConstraintSystemWithLazy<F>
where
    F: PrimeField,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    fn from(cs: LegacyConstraintSystem<F>) -> Self {
        Self {
            public: cs.public,
            prev_challenges: cs.prev_challenges,
            domain: cs.domain,
            gates: cs.gates,
            zk_rows: cs.zk_rows,
            feature_flags: cs.feature_flags,
            lazy_mode: false,
            sid: cs.sid,
            shift: cs.shift,
            endo: cs.endo,
            lookup_constraint_system: cs.lookup_constraint_system,
            disable_gates_checks: cs.disable_gates_checks,
        }
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
    <IpaOpeningProof<C> as OpenProof<C>>::SRS: Default,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    fn upgrade(self) -> Result<ProverIndex<C, IpaOpeningProof<C>>, String> {
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
) -> Result<ProverIndex<C, IpaOpeningProof<C>>, JsError>
where
    F: PrimeField,
    C: AffineRepr<ScalarField = F> + KimchiCurve<ScalarField = F>,
    C::BaseField: PrimeField,
    IpaOpeningProof<C>: OpenProof<C>,
    <IpaOpeningProof<C> as OpenProof<C>>::SRS: Default,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    let mut primary = rmp_serde::Deserializer::new(bytes);
    match ProverIndex::<C, IpaOpeningProof<C>>::deserialize(&mut primary) {
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
