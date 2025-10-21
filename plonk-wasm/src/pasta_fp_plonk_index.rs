use crate::{
    gate_vector::fp::WasmGateVector,
    srs::fp::WasmFpSrs as WasmSrs,
    wasm_vector::{fp::*, WasmVector},
};
use ark_poly::EvaluationDomain;
use arkworks::WasmPastaFp;
use ark_ec::AffineRepr;
use kimchi::{
    circuits::{
        constraints::{ColumnEvaluations, ConstraintSystem},
        gate::CircuitGate,
        lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    },
    linearization::expr_linearization,
    o1_utils::lazy_cache::LazyCache,
    poly_commitment::{ipa::OpeningProof, SRS as _},
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Pallas as GAffineOther, Vesta as GAffine, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use serde::{Deserialize, Serialize};
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

type PastaFpProverIndex = ProverIndex<GAffine, OpeningProof<GAffine>>;
type PastaFpBaseField = <GAffine as AffineRepr>::BaseField;

#[serde_as]
#[derive(Serialize, Deserialize)]
struct SerializablePastaFpProverIndex {
    cs: Arc<ConstraintSystem<Fp>>,
    max_poly_size: usize,
    column_evaluations: Arc<LazyCache<ColumnEvaluations<Fp>>>,
    #[serde(default)]
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    verifier_index_digest: Option<PastaFpBaseField>,
}

fn to_serializable_index(index: &PastaFpProverIndex) -> SerializablePastaFpProverIndex {
    let mut serializable = SerializablePastaFpProverIndex {
        cs: Arc::clone(&index.cs),
        max_poly_size: index.max_poly_size,
        column_evaluations: Arc::clone(&index.column_evaluations),
        verifier_index_digest: index.verifier_index_digest.clone(),
    };
    customize_serialized_index(&mut serializable);
    serializable
}

fn from_serializable_index(serialized: SerializablePastaFpProverIndex) -> PastaFpProverIndex {
    let (linearization, powers_of_alpha) =
        expr_linearization(Some(&serialized.cs.feature_flags), true);

    PastaFpProverIndex {
        cs: serialized.cs,
        linearization,
        powers_of_alpha,
        srs: Arc::new(Default::default()),
        max_poly_size: serialized.max_poly_size,
        column_evaluations: serialized.column_evaluations,
        verifier_index: None,
        verifier_index_digest: serialized.verifier_index_digest,
    }
}

// Hook for adjusting serialized fields before they are written out.
fn customize_serialized_index(_index: &mut SerializablePastaFpProverIndex) {}

// Hook for updating the in-memory index right after deserialization.
fn customize_deserialized_index(_index: &mut PastaFpProverIndex) {}

fn deserialize_pasta_fp_prover_index(bytes: &[u8]) -> Result<PastaFpProverIndex, String> {
    match rmp_serde::from_slice::<SerializablePastaFpProverIndex>(bytes) {
        Ok(serialized) => Ok(from_serializable_index(serialized)),
        Err(manual_err) => {
            let mut deserializer = rmp_serde::Deserializer::new(bytes);
            ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(&mut deserializer).map_err(
                |fallback_err| {
                    format!(
                        "manual decode failed ({manual_err}); fallback decode failed ({fallback_err})"
                    )
                },
            )
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
    let mut index = deserialize_pasta_fp_prover_index(bytes)
        .map_err(|err| JsError::new(&format!("caml_pasta_fp_plonk_index_decode: {}", err)))?;
    index.srs = srs.0.clone();
    customize_deserialized_index(&mut index);

    Ok(WasmPastaFpPlonkIndex(Box::new(index)))
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_encode(index: &WasmPastaFpPlonkIndex) -> Result<Vec<u8>, JsError> {
    let mut buffer = Vec::new();
    let mut serializer = rmp_serde::Serializer::new(&mut buffer).with_struct_map();
    let data = to_serializable_index(&index.0);
    data.serialize(&mut serializer)
        .map_err(|e| JsError::new(&format!("caml_pasta_fp_plonk_index_encode: {}", e)))?;
    Ok(buffer)
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_read(
    offset: Option<i32>,
    srs: &WasmSrs,
    path: String,
) -> Result<WasmPastaFpPlonkIndex, JsValue> {
    let path_for_err = path.clone();
    // read from file
    let file = match File::open(&path) {
        Err(_) => {
            return Err(JsValue::from_str(&format!(
                "caml_pasta_fp_plonk_index_read({path_for_err}): could not open file"
            )))
        }
        Ok(file) => file,
    };
    let mut r = BufReader::new(file);

    // optional offset in file
    if let Some(offset) = offset {
        r.seek(Start(offset as u64))
            .map_err(|err| JsValue::from_str(&format!(
                "caml_pasta_fp_plonk_index_read({path_for_err}): {err}"
            )))?;
    }

    // deserialize the index
    let mut data = Vec::new();
    r.read_to_end(&mut data)
        .map_err(|err| JsValue::from_str(&format!(
            "caml_pasta_fp_plonk_index_read({path_for_err}): {err}"
        )))?;
    let mut t = deserialize_pasta_fp_prover_index(&data)
        .map_err(|err| JsValue::from_str(&format!(
            "caml_pasta_fp_plonk_index_read({path_for_err}): {err}"
        )))?;
    t.srs = srs.0.clone();
    customize_deserialized_index(&mut t);

    //
    Ok(WasmPastaFpPlonkIndex(Box::new(t)))
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
    let data = to_serializable_index(&index.0);
    data.serialize(&mut rmp_serde::Serializer::new(w).with_struct_map())
        .map_err(|e| JsValue::from_str(&format!("caml_pasta_fp_plonk_index_write: {e}")))
}

#[allow(deprecated)]
#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_serialize(index: &WasmPastaFpPlonkIndex) -> String {
    let mut buffer = Vec::new();
    {
        let mut serializer = rmp_serde::Serializer::new(&mut buffer).with_struct_map();
        let data = to_serializable_index(&index.0);
        data.serialize(&mut serializer).unwrap();
    }
    // Deprecated used on purpose: updating this leads to a bug in o1js
    base64::encode(buffer)
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
