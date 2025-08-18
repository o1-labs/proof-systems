use crate::{
    gate_vector::fp::WasmGateVector,
    srs::fp::WasmFpSrs as WasmSrs,
    wasm_vector::{fp::*, WasmVector},
    memory_tracker::{next_id, log_allocation, log_deallocation},
};
use ark_poly::EvaluationDomain;
use arkworks::WasmPastaFp;
use kimchi::{
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    },
    linearization::expr_linearization,
    poly_commitment::{ipa::OpeningProof, SRS as _},
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Pallas as GAffineOther, Vesta as GAffine, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom::Start},
};
use wasm_bindgen::prelude::*;
use wasm_types::FlatVector as WasmFlatVector;

//
// CamlPastaFpPlonkIndex (custom type)
//

/// Boxed so that we don't store large proving indexes in the OCaml heap.
#[wasm_bindgen]
pub struct WasmPastaFpPlonkIndex {
    #[wasm_bindgen(skip)] 
    pub index: Box<ProverIndex<GAffine, OpeningProof<GAffine>>>,
    #[wasm_bindgen(skip)]
    pub id: u64,
}

impl WasmPastaFpPlonkIndex {
    fn calculate_size(&self) -> usize {
        // Base struct size
        let mut size = std::mem::size_of::<Self>();
        
        // ProverIndex is boxed, add its size
        size += std::mem::size_of_val(&*self.index);
        
        // Add constraint system gates size
        size += self.index.cs.gates.len() * std::mem::size_of::<kimchi::circuits::gate::CircuitGate<Fp>>();
        
        // Add domain sizes (polynomials)
        size += self.index.cs.domain.d1.size() * std::mem::size_of::<Fp>();
        size += self.index.cs.domain.d4.size() * std::mem::size_of::<Fp>();
        size += self.index.cs.domain.d8.size() * std::mem::size_of::<Fp>();
        
        size
    }
}

impl Drop for WasmPastaFpPlonkIndex {
    fn drop(&mut self) {
        let size = self.calculate_size();
        crate::memory_tracker::log_deallocation("WasmPastaFpPlonkIndex", size, self.id);
    }
}

// This should mimic LookupTable structure
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPastaFpLookupTable {
    #[wasm_bindgen(skip)]
    pub table_id: i32,
    #[wasm_bindgen(skip)]
    pub data: WasmVecVecFp,
    #[wasm_bindgen(skip)]
    pub tracker_id: u64,
}

impl Drop for WasmPastaFpLookupTable {
    fn drop(&mut self) {
        let size = std::mem::size_of::<i32>() + crate::memory_tracker::estimate_nested_vec_size(&self.data.data);
        crate::memory_tracker::log_deallocation("WasmPastaFpLookupTable", size, self.tracker_id);
    }
}

// Converter from WasmPastaFpLookupTable to LookupTable, used by the binding
// below.
impl From<WasmPastaFpLookupTable> for LookupTable<Fp> {
    fn from(wasm_lt: WasmPastaFpLookupTable) -> LookupTable<Fp> {
        LookupTable {
            id: wasm_lt.table_id,
            data: wasm_lt.data.data.clone(),
        }
    }
}

// JS constructor for js/bindings.js
#[wasm_bindgen]
impl WasmPastaFpLookupTable {
    #[wasm_bindgen(constructor)]
    pub fn new(id: i32, data: WasmVecVecFp) -> WasmPastaFpLookupTable {
        let tracker_id = crate::memory_tracker::next_id();
        let size = std::mem::size_of::<i32>() + crate::memory_tracker::estimate_nested_vec_size(&data.data);
        crate::memory_tracker::log_allocation("WasmPastaFpLookupTable", size, file!(), line!(), tracker_id);
        WasmPastaFpLookupTable { table_id: id, data, tracker_id }
    }
}

// Runtime table config

#[wasm_bindgen]
#[derive(Clone)]
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
            .data
            .iter()
            .map(|gate| CircuitGate::<Fp> {
                typ: gate.typ,
                wires: gate.wires,
                coeffs: gate.coeffs.clone(),
            })
            .collect();

        let rust_runtime_table_cfgs: Vec<RuntimeTableCfg<Fp>> =
            runtime_table_cfgs.data.clone().into_iter().map(Into::into).collect();

        let rust_lookup_tables: Vec<LookupTable<Fp>> =
            lookup_tables.data.clone().into_iter().map(Into::into).collect();

        // create constraint system
        let cs = match ConstraintSystem::<Fp>::create(gates)
            .public(public_ as usize)
            .prev_challenges(prev_challenges as usize)
            .lookup(rust_lookup_tables)
            .max_poly_size(Some(srs.srs.max_poly_size()))
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

        srs.srs.get_lagrange_basis(cs.domain.d1);

        let mut index = ProverIndex::<GAffine, OpeningProof<GAffine>>::create(
            cs,
            endo_q,
            srs.srs.clone(),
            lazy_mode,
        );
        // Compute and cache the verifier index digest
        index.compute_verifier_index_digest::<DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>();
        Ok(index)
    });

    // create index
    match index {
        Ok(index) => {
            let boxed_index = Box::new(index);
            let id = crate::memory_tracker::next_id();
            // Calculate actual size
            let mut size = std::mem::size_of::<WasmPastaFpPlonkIndex>();
            size += std::mem::size_of_val(&*boxed_index);
            size += boxed_index.cs.gates.len() * std::mem::size_of::<kimchi::circuits::gate::CircuitGate<Fp>>();
            size += boxed_index.cs.domain.d1.size() * std::mem::size_of::<Fp>();
            size += boxed_index.cs.domain.d4.size() * std::mem::size_of::<Fp>();
            size += boxed_index.cs.domain.d8.size() * std::mem::size_of::<Fp>();
            crate::memory_tracker::log_allocation("WasmPastaFpPlonkIndex", size, file!(), line!(), id);
            Ok(WasmPastaFpPlonkIndex { index: boxed_index, id })
        },
        Err(str) => Err(JsError::new(str)),
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_max_degree(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.index.srs.max_poly_size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_public_inputs(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.index.cs.public as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_domain_d1_size(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.index.cs.domain.d1.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_domain_d4_size(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.index.cs.domain.d4.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_domain_d8_size(index: &WasmPastaFpPlonkIndex) -> i32 {
    index.index.cs.domain.d8.size() as i32
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_decode(
    bytes: &[u8],
    srs: &WasmSrs,
) -> Result<WasmPastaFpPlonkIndex, JsError> {
    let mut deserializer = rmp_serde::Deserializer::new(bytes);
    let mut index =
        ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(&mut deserializer)
            .map_err(|e| JsError::new(&format!("caml_pasta_fp_plonk_index_decode: {}", e)))?;

    index.srs = srs.srs.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&index.cs.feature_flags), true);
    index.linearization = linearization;
    index.powers_of_alpha = powers_of_alpha;

    let boxed_index = Box::new(index);
    let id = next_id();
    // Calculate actual size
    let mut size = std::mem::size_of::<WasmPastaFpPlonkIndex>();
    size += std::mem::size_of_val(&*boxed_index);
    size += boxed_index.cs.gates.len() * std::mem::size_of::<kimchi::circuits::gate::CircuitGate<Fp>>();
    size += boxed_index.cs.domain.d1.size() * std::mem::size_of::<Fp>();
    size += boxed_index.cs.domain.d4.size() * std::mem::size_of::<Fp>();
    size += boxed_index.cs.domain.d8.size() * std::mem::size_of::<Fp>();
    log_allocation("WasmPastaFpPlonkIndex", size, file!(), line!(), id);
    Ok(WasmPastaFpPlonkIndex { index: boxed_index, id })
}

#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_encode(index: &WasmPastaFpPlonkIndex) -> Result<Vec<u8>, JsError> {
    let mut buffer = Vec::new();
    let mut serializer = rmp_serde::Serializer::new(&mut buffer);
    index
        .index
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

    // deserialize the index
    let mut t = ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(
        &mut rmp_serde::Deserializer::new(r),
    )
    .map_err(|err| JsValue::from_str(&format!("caml_pasta_fp_plonk_index_read: {err}")))?;
    t.srs = srs.srs.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&t.cs.feature_flags), true);
    t.linearization = linearization;
    t.powers_of_alpha = powers_of_alpha;

    let boxed_index = Box::new(t);
    let id = crate::memory_tracker::next_id();
    let mut size = std::mem::size_of::<WasmPastaFpPlonkIndex>();
    size += std::mem::size_of_val(&*boxed_index);
    size += boxed_index.cs.gates.len() * std::mem::size_of::<kimchi::circuits::gate::CircuitGate<Fp>>();
    size += boxed_index.cs.domain.d1.size() * std::mem::size_of::<Fp>();
    size += boxed_index.cs.domain.d4.size() * std::mem::size_of::<Fp>();
    size += boxed_index.cs.domain.d8.size() * std::mem::size_of::<Fp>();
    crate::memory_tracker::log_allocation("WasmPastaFpPlonkIndex", size, file!(), line!(), id);
    Ok(WasmPastaFpPlonkIndex { index: boxed_index, id })
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
        .index
        .serialize(&mut rmp_serde::Serializer::new(w))
        .map_err(|e| JsValue::from_str(&format!("caml_pasta_fp_plonk_index_read: {e}")))
}

#[allow(deprecated)]
#[wasm_bindgen]
pub fn caml_pasta_fp_plonk_index_serialize(index: &WasmPastaFpPlonkIndex) -> String {
    let serialized = rmp_serde::to_vec(&index.index).unwrap();
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
