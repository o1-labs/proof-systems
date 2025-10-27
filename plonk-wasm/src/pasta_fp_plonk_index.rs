use crate::{
    gate_vector::fp::WasmGateVector,
    srs::fp::WasmFpSrs as WasmSrs,
    wasm_vector::{fp::*, WasmVector},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use arkworks::WasmPastaFp;
use kimchi::{
    circuits::{
        constraints::{ColumnEvaluations, ConstraintSystem, FeatureFlags},
        domains::EvaluationDomains,
        gate::CircuitGate,
        lookup::{
            index::{LookupConstraintSystem, LookupError},
            runtime_tables::RuntimeTableCfg,
            tables::LookupTable,
        },
        wires::PERMUTS,
    },
    linearization::expr_linearization,
    poly_commitment::{ipa::OpeningProof, SRS as _},
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Pallas as GAffineOther, Vesta as GAffine, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use o1_utils::lazy_cache::LazyCache;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom::Start},
    sync::Arc,
};
use wasm_bindgen::prelude::*;
use wasm_types::FlatVector as WasmFlatVector;

//
// CamlPastaFpPlonkIndex (custom type)
//

/// Boxed so that we don't store large proving indexes in the OCaml heap.
#[wasm_bindgen]
pub struct WasmPastaFpPlonkIndex(
    #[wasm_bindgen(skip)] pub Box<ProverIndex<GAffine, OpeningProof<GAffine>>>,
);

// This should mimic LookupTable structure
#[wasm_bindgen]
pub struct WasmPastaFpLookupTable {
    #[wasm_bindgen(skip)]
    pub id: i32,
    #[wasm_bindgen(skip)]
    pub data: WasmVecVecFp,
}

// Converter from WasmPastaFpLookupTable to LookupTable, used by the binding
// below.
impl From<WasmPastaFpLookupTable> for LookupTable<Fp> {
    fn from(wasm_lt: WasmPastaFpLookupTable) -> LookupTable<Fp> {
        LookupTable {
            id: wasm_lt.id,
            data: wasm_lt.data.0,
        }
    }
}

// JS constructor for js/bindings.js
#[wasm_bindgen]
impl WasmPastaFpLookupTable {
    #[wasm_bindgen(constructor)]
    pub fn new(id: i32, data: WasmVecVecFp) -> WasmPastaFpLookupTable {
        WasmPastaFpLookupTable { id, data }
    }
}

// Runtime table config

#[wasm_bindgen]
pub struct WasmPastaFpRuntimeTableCfg {
    #[wasm_bindgen(skip)]
    pub id: i32,
    #[wasm_bindgen(skip)]
    pub first_column: WasmFlatVector<WasmPastaFp>,
}

// JS constructor for js/bindings.js
#[wasm_bindgen]
impl WasmPastaFpRuntimeTableCfg {
    #[wasm_bindgen(constructor)]
    pub fn new(id: i32, first_column: WasmFlatVector<WasmPastaFp>) -> Self {
        Self { id, first_column }
    }
}

impl From<WasmPastaFpRuntimeTableCfg> for RuntimeTableCfg<Fp> {
    fn from(wasm_rt_table_cfg: WasmPastaFpRuntimeTableCfg) -> Self {
        Self {
            id: wasm_rt_table_cfg.id,
            first_column: wasm_rt_table_cfg
                .first_column
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

// CamlPastaFpPlonkIndex methods
//

// Change js/web/worker-spec.js accordingly
#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_create(
    gates: &WasmGateVector,
    public_: i32,
    lookup_tables: WasmVector<WasmPastaFpLookupTable>,
    runtime_table_cfgs: WasmVector<WasmPastaFpRuntimeTableCfg>,
    prev_challenges: i32,
    srs: &WasmSrs,
    lazy_mode: bool,
) -> Result<WasmPastaFpPlonkIndex, JsError> {
    console_error_panic_hook::set_once();
    let index = crate::rayon::run_in_pool(|| {
        // flatten the permutation information (because OCaml has a different way of keeping track of permutations)
        let gates: Vec<_> = gates
            .0
            .iter()
            .map(|gate| CircuitGate::<Fp> {
                typ: gate.typ,
                wires: gate.wires,
                coeffs: gate.coeffs.clone(),
            })
            .collect();

        let rust_runtime_table_cfgs: Vec<RuntimeTableCfg<Fp>> =
            runtime_table_cfgs.into_iter().map(Into::into).collect();

        let rust_lookup_tables: Vec<LookupTable<Fp>> =
            lookup_tables.into_iter().map(Into::into).collect();

        // create constraint system
        let cs = match ConstraintSystem::<Fp>::create(gates)
            .public(public_ as usize)
            .prev_challenges(prev_challenges as usize)
            .lookup(rust_lookup_tables)
            .max_poly_size(Some(srs.0.max_poly_size()))
            .runtime(if rust_runtime_table_cfgs.is_empty() {
                None
            } else {
                Some(rust_runtime_table_cfgs)
            })
            .lazy_mode(lazy_mode)
            .build()
        {
            Err(_) => {
                return Err("caml_pasta_fp_plonk_index_create: could not create constraint system");
            }
            Ok(cs) => cs,
        };

        // endo
        let (endo_q, _endo_r) = poly_commitment::ipa::endos::<GAffineOther>();

        srs.0.get_lagrange_basis(cs.domain.d1);

        let mut index = ProverIndex::<GAffine, OpeningProof<GAffine>>::create(
            cs,
            endo_q,
            srs.0.clone(),
            lazy_mode,
        );
        // Compute and cache the verifier index digest
        index.compute_verifier_index_digest::<DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>();
        Ok(index)
    });

    // create index
    match index {
        Ok(index) => Ok(WasmPastaFpPlonkIndex(Box::new(index))),
        Err(str) => Err(JsError::new(str)),
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_max_degree(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.0.srs.max_poly_size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_public_inputs(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.0.cs.public as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_domain_d1_size(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.0.cs.domain.d1.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_domain_d4_size(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.0.cs.domain.d4.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_domain_d8_size(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.0.cs.domain.d8.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_decode(
    bytes: &[u8],
    srs: &WasmSrs,
) -> Result<WasmPastaFpPlonkIndex, JsError> {
    let mut index = deserialize_index_with_fallback(bytes, "caml_pasta_fp_plonk_index_decode")?;

    index.srs = srs.0.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&index.cs.feature_flags), true);
    index.linearization = linearization;
    index.powers_of_alpha = powers_of_alpha;

    Ok(WasmPastaFpPlonkIndex(Box::new(index)))
}

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
struct LegacyProverIndexFp {
    cs: LegacyConstraintSystem<Fp>,
    max_poly_size: usize,
    column_evaluations: Arc<LazyCache<ColumnEvaluations<Fp>>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    verifier_index_digest: Option<<GAffine as AffineRepr>::BaseField>,
}

impl LegacyProverIndexFp {
    fn upgrade(self) -> Result<ProverIndex<GAffine, OpeningProof<GAffine>>, String> {
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

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_encode(index: &WasmPastaFpPlonkIndex) -> Result<Vec<u8>, JsError> {
    let mut buffer = Vec::new();
    let mut serializer = rmp_serde::Serializer::new(&mut buffer).with_struct_map();
    index
        .0
        .serialize(&mut serializer)
        .map_err(|e| JsError::new(&format!("caml_pasta_fp_plonk_index_encode: {}", e)))?;
    Ok(buffer)
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_read(
    offset: Option<i32>,
    srs: &WasmSrs,
    path: String,
) -> Result<WasmPastaFpPlonkIndex, JsValue> {
    // read from file
    let file = match File::open(path) {
        Err(_) => return Err(JsValue::from_str("caml_pasta_fp_plonk_index_read")),
        Ok(file) => file,
    };
    let mut r = BufReader::new(file);

    // optional offset in file
    if let Some(offset) = offset {
        r.seek(Start(offset as u64))
            .map_err(|err| JsValue::from_str(&format!("caml_pasta_fp_plonk_index_read: {err}")))?;
    }

    let mut bytes = Vec::new();
    r.read_to_end(&mut bytes)
        .map_err(|err| JsValue::from_str(&format!("caml_pasta_fp_plonk_index_read: {err}")))?;

    // deserialize the index
    let mut t = deserialize_index_with_fallback(&bytes, "caml_pasta_fp_plonk_index_read")
        .map_err(JsValue::from)?;
    t.srs = srs.0.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&t.cs.feature_flags), true);
    t.linearization = linearization;
    t.powers_of_alpha = powers_of_alpha;

    //
    Ok(WasmPastaFpPlonkIndex(Box::new(t)))
}

fn deserialize_index_with_fallback(
    bytes: &[u8],
    context: &str,
) -> Result<ProverIndex<GAffine, OpeningProof<GAffine>>, JsError> {
    let mut primary = rmp_serde::Deserializer::new(bytes);
    match ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(&mut primary) {
        Ok(index) => Ok(index),
        Err(primary_err) => {
            let mut fallback = rmp_serde::Deserializer::new(bytes);
            let legacy = LegacyProverIndexFp::deserialize(&mut fallback).map_err(|legacy_err| {
                JsError::new(&format!(
                    "{context}: {primary_err}; legacy decode failed: {legacy_err}"
                ))
            })?;
            let upgraded = legacy
                .upgrade()
                .map_err(|err| JsError::new(&format!("{context}: {err}")))?;
            Ok(upgraded)
        }
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_write(
    append: Option<bool>,
    index: &WasmPastaFpPlonkIndex,
    path: String,
) -> Result<(), JsValue> {
    let file = OpenOptions::new()
        .append(append.unwrap_or(true))
        .open(path)
        .map_err(|_| JsValue::from_str("caml_pasta_fp_plonk_index_write"))?;
    let w = BufWriter::new(file);
    index
        .0
        .serialize(&mut rmp_serde::Serializer::new(w).with_struct_map())
        .map_err(|e| JsValue::from_str(&format!("caml_pasta_fp_plonk_index_read: {e}")))
}

#[allow(deprecated)]
#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_serialize(index: &WasmPastaFpPlonkIndex) -> String {
    let serialized = rmp_serde::to_vec(&index.0).unwrap();
    // Deprecated used on purpose: updating this leads to a bug in o1js
    base64::encode(serialized)
}

// helpers

fn format_field(f: &Fp) -> String {
    // TODO this could be much nicer, should end up as "1", "-1", "0" etc
    format!("{f}")
}

pub fn format_circuit_gate(i: usize, gate: &CircuitGate<Fp>) -> String {
    let coeffs = gate
        .coeffs
        .iter()
        .map(format_field)
        .collect::<Vec<_>>()
        .join("\n");
    let wires = gate
        .wires
        .iter()
        .enumerate()
        .filter(|(j, wire)| wire.row != i || wire.col != *j)
        .map(|(j, wire)| format!("({}, {}) --> ({}, {})", i, j, wire.row, wire.col))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "c[{}][{:?}]:\nconstraints\n{}\nwires\n{}\n",
        i, gate.typ, coeffs, wires
    )
}
