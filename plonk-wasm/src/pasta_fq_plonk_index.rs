use crate::{
    gate_vector::fq::WasmGateVector,
    srs::fq::WasmFqSrs as WasmSrs,
    wasm_vector::{fq::*, WasmVector},
};
use ark_ec::AffineRepr;
use ark_poly::EvaluationDomain;
use arkworks::WasmPastaFq;
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
use mina_curves::pasta::{Fq, Pallas as GAffine, PallasParameters, Vesta as GAffineOther};
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
// CamlPastaFqPlonkIndex (custom type)
//

/// Boxed so that we don't store large proving indexes in the OCaml heap.
#[wasm_bindgen]
pub struct WasmPastaFqPlonkIndex(
    #[wasm_bindgen(skip)] pub Box<ProverIndex<GAffine, OpeningProof<GAffine>>>,
);

#[wasm_bindgen]
pub struct WasmPastaFqLookupTable {
    #[wasm_bindgen(skip)]
    pub id: i32,
    #[wasm_bindgen(skip)]
    pub data: WasmVecVecFq,
}

impl From<WasmPastaFqLookupTable> for LookupTable<Fq> {
    fn from(wasm_lt: WasmPastaFqLookupTable) -> LookupTable<Fq> {
        LookupTable {
            id: wasm_lt.id,
            data: wasm_lt.data.0,
        }
    }
}

// JS constructor for js/bindings.js
#[wasm_bindgen]
impl WasmPastaFqLookupTable {
    #[wasm_bindgen(constructor)]
    pub fn new(id: i32, data: WasmVecVecFq) -> WasmPastaFqLookupTable {
        WasmPastaFqLookupTable { id, data }
    }
}

// Runtime table config

#[wasm_bindgen]
pub struct WasmPastaFqRuntimeTableCfg {
    #[wasm_bindgen(skip)]
    pub id: i32,
    #[wasm_bindgen(skip)]
    pub first_column: WasmFlatVector<WasmPastaFq>,
}

impl From<WasmPastaFqRuntimeTableCfg> for RuntimeTableCfg<Fq> {
    fn from(wasm_rt_cfg: WasmPastaFqRuntimeTableCfg) -> Self {
        Self {
            id: wasm_rt_cfg.id,
            first_column: wasm_rt_cfg
                .first_column
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

type PastaFqProverIndex = ProverIndex<GAffine, OpeningProof<GAffine>>;
type PastaFqBaseField = <GAffine as AffineRepr>::BaseField;

#[serde_as]
#[derive(Serialize, Deserialize)]
struct SerializablePastaFqProverIndex {
    cs: Arc<ConstraintSystem<Fq>>,
    max_poly_size: usize,
    column_evaluations: Arc<LazyCache<ColumnEvaluations<Fq>>>,
    #[serde(default)]
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    verifier_index_digest: Option<PastaFqBaseField>,
}

fn to_serializable_index(index: &PastaFqProverIndex) -> SerializablePastaFqProverIndex {
    let mut serializable = SerializablePastaFqProverIndex {
        cs: Arc::clone(&index.cs),
        max_poly_size: index.max_poly_size,
        column_evaluations: Arc::clone(&index.column_evaluations),
        verifier_index_digest: index.verifier_index_digest.clone(),
    };
    serializable
}

fn from_serializable_index(serialized: SerializablePastaFqProverIndex) -> PastaFqProverIndex {
    let (linearization, powers_of_alpha) =
        expr_linearization(Some(&serialized.cs.feature_flags), true);

    PastaFqProverIndex {
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

fn deserialize_pasta_fq_prover_index(bytes: &[u8]) -> Result<PastaFqProverIndex, String> {
    match rmp_serde::from_slice::<SerializablePastaFqProverIndex>(bytes) {
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

// JS constructor for js/bindings.js
#[wasm_bindgen]
impl WasmPastaFqRuntimeTableCfg {
    #[wasm_bindgen(constructor)]
    pub fn new(id: i32, first_column: WasmFlatVector<WasmPastaFq>) -> Self {
        Self { id, first_column }
    }
}

//
// CamlPastaFqPlonkIndex methods
//

// Change js/web/worker-spec.js accordingly
#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_create(
    gates: &WasmGateVector,
    public_: i32,
    lookup_tables: WasmVector<WasmPastaFqLookupTable>,
    runtime_table_cfgs: WasmVector<WasmPastaFqRuntimeTableCfg>,
    prev_challenges: i32,
    srs: &WasmSrs,
    lazy_mode: bool,
) -> Result<WasmPastaFqPlonkIndex, JsError> {
    console_error_panic_hook::set_once();
    let index = crate::rayon::run_in_pool(|| {
        // flatten the permutation information (because OCaml has a different way of keeping track of permutations)
        let gates: Vec<_> = gates
            .0
            .iter()
            .map(|gate| CircuitGate::<Fq> {
                typ: gate.typ,
                wires: gate.wires,
                coeffs: gate.coeffs.clone(),
            })
            .collect();

        let rust_runtime_table_cfgs: Vec<RuntimeTableCfg<Fq>> =
            runtime_table_cfgs.into_iter().map(Into::into).collect();

        let rust_lookup_tables: Vec<LookupTable<Fq>> =
            lookup_tables.into_iter().map(Into::into).collect();

        // create constraint system
        let cs = match ConstraintSystem::<Fq>::create(gates)
            .public(public_ as usize)
            .prev_challenges(prev_challenges as usize)
            .lookup(rust_lookup_tables)
            .runtime(if rust_runtime_table_cfgs.is_empty() {
                None
            } else {
                Some(rust_runtime_table_cfgs)
            })
            .lazy_mode(lazy_mode)
            .build()
        {
            Err(_) => {
                return Err("caml_pasta_fq_plonk_index_create: could not create constraint system");
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
        index.compute_verifier_index_digest::<DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>>();

        Ok(index)
    });

    // create index
    match index {
        Ok(index) => Ok(WasmPastaFqPlonkIndex(Box::new(index))),
        Err(str) => Err(JsError::new(str)),
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_max_degree(index: &WasmPastaFqPlonkIndex) -> i32 {
    index.0.srs.max_poly_size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_public_inputs(index: &WasmPastaFqPlonkIndex) -> i32 {
    index.0.cs.public as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_domain_d1_size(index: &WasmPastaFqPlonkIndex) -> i32 {
    index.0.cs.domain.d1.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_domain_d4_size(index: &WasmPastaFqPlonkIndex) -> i32 {
    index.0.cs.domain.d4.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_domain_d8_size(index: &WasmPastaFqPlonkIndex) -> i32 {
    index.0.cs.domain.d8.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_decode(
    bytes: &[u8],
    srs: &WasmSrs,
) -> Result<WasmPastaFqPlonkIndex, JsError> {
    let mut index = deserialize_pasta_fq_prover_index(bytes)
        .map_err(|err| JsError::new(&format!("caml_pasta_fq_plonk_index_decode: {}", err)))?;

    index.srs = srs.0.clone();

    Ok(WasmPastaFqPlonkIndex(Box::new(index)))
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_encode(index: &WasmPastaFqPlonkIndex) -> Result<Vec<u8>, JsError> {
    let mut buffer = Vec::new();
    let mut serializer = rmp_serde::Serializer::new(&mut buffer).with_struct_map();
    let data = to_serializable_index(&index.0);
    data.serialize(&mut serializer)
        .map_err(|e| JsError::new(&format!("caml_pasta_fq_plonk_index_encode: {}", e)))?;
    Ok(buffer)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_read(
    offset: Option<i32>,
    srs: &WasmSrs,
    path: String,
) -> Result<WasmPastaFqPlonkIndex, JsValue> {
    let path_for_err = path.clone();
    // read from file
    let file = match File::open(&path) {
        Err(_) => {
            return Err(JsValue::from_str(&format!(
                "caml_pasta_fq_plonk_index_read({path_for_err}): could not open file"
            )))
        }
        Ok(file) => file,
    };
    let mut r = BufReader::new(file);

    // optional offset in file
    if let Some(offset) = offset {
        r.seek(Start(offset as u64)).map_err(|err| {
            JsValue::from_str(&format!(
                "caml_pasta_fq_plonk_index_read({path_for_err}): {err}"
            ))
        })?;
    }

    // deserialize the index
    let mut data = Vec::new();
    r.read_to_end(&mut data).map_err(|err| {
        JsValue::from_str(&format!(
            "caml_pasta_fq_plonk_index_read({path_for_err}): {err}"
        ))
    })?;
    let mut t = deserialize_pasta_fq_prover_index(&data).map_err(|err| {
        JsValue::from_str(&format!(
            "caml_pasta_fq_plonk_index_read({path_for_err}): {err}"
        ))
    })?;
    t.srs = srs.0.clone();

    //
    Ok(WasmPastaFqPlonkIndex(Box::new(t)))
}

#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_write(
    append: Option<bool>,
    index: &WasmPastaFqPlonkIndex,
    path: String,
) -> Result<(), JsValue> {
    let file = OpenOptions::new()
        .append(append.unwrap_or(true))
        .open(path)
        .map_err(|_| JsValue::from_str("caml_pasta_fq_plonk_index_write"))?;
    let w = BufWriter::new(file);
    let data = to_serializable_index(&index.0);
    data.serialize(&mut rmp_serde::Serializer::new(w).with_struct_map())
        .map_err(|e| JsValue::from_str(&format!("caml_pasta_fq_plonk_index_write: {e}")))
}

#[allow(deprecated)]
#[wasm_bindgen]
pub fn caml_pasta_fq_plonk_index_serialize(index: &WasmPastaFqPlonkIndex) -> String {
    let mut buffer = Vec::new();
    {
        let mut serializer = rmp_serde::Serializer::new(&mut buffer).with_struct_map();
        let data = to_serializable_index(&index.0);
        data.serialize(&mut serializer).unwrap();
    }
    // Deprecated used on purpose: updating this leads to a bug in o1js
    base64::encode(buffer)
}
