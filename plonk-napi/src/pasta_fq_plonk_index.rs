use ark_poly::EvaluationDomain;
use kimchi::circuits::constraints::ConstraintSystem;
use kimchi::{linearization::expr_linearization, prover_index::ProverIndex};
use mina_curves::pasta::{Fq, Pallas as GAffine, PallasParameters, Vesta as GAffineOther};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use napi::bindgen_prelude::{Error, External, Result as NapiResult, Status, Uint8Array};
use napi_derive::napi;
use crate::gate_vector::NapiFqGateVector;
use poly_commitment::ipa::{OpeningProof, SRS as IPA_SRS};
use poly_commitment::SRS;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Seek, SeekFrom::Start};
use std::{io::Cursor, sync::Arc};

use crate::tables::{
    lookup_table_fq_from_js, runtime_table_cfg_fq_from_js, JsLookupTableFq, JsRuntimeTableCfgFq,
};
use plonk_wasm::srs::fq::WasmFqSrs as WasmSrs;
pub struct WasmPastaFqPlonkIndex(pub Box<ProverIndex<GAffine, OpeningProof<GAffine>>>);

#[derive(Serialize, Deserialize)]
struct SerializedProverIndex {
    prover_index: Vec<u8>,
    srs: Vec<u8>,
}

impl WasmPastaFqPlonkIndex {
    fn serialize_inner(&self) -> Result<Vec<u8>, String> {
        let prover_index = rmp_serde::to_vec(self.0.as_ref()).map_err(|e| e.to_string())?;

        let mut srs = Vec::new();
        self.0
            .srs
            .serialize(&mut rmp_serde::Serializer::new(&mut srs))
            .map_err(|e| e.to_string())?;

        let serialized = SerializedProverIndex { prover_index, srs };

        rmp_serde::to_vec(&serialized).map_err(|e| e.to_string())
    }

    fn deserialize_inner(bytes: &[u8]) -> Result<Self, String> {
        let serialized: SerializedProverIndex =
            rmp_serde::from_slice(bytes).map_err(|e| e.to_string())?;

        let mut index: ProverIndex<GAffine, OpeningProof<GAffine>> = ProverIndex::deserialize(
            &mut rmp_serde::Deserializer::new(Cursor::new(serialized.prover_index)),
        )
        .map_err(|e| e.to_string())?;

        let srs = IPA_SRS::<GAffine>::deserialize(&mut rmp_serde::Deserializer::new(Cursor::new(
            serialized.srs,
        )))
        .map_err(|e| e.to_string())?;

        index.srs = Arc::new(srs);

        let (linearization, powers_of_alpha) =
            expr_linearization(Some(&index.cs.feature_flags), true);
        index.linearization = linearization;
        index.powers_of_alpha = powers_of_alpha;

        index.compute_verifier_index_digest::<
            DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>,
        >();

        Ok(WasmPastaFqPlonkIndex(Box::new(index)))
    }
}

#[napi]
pub fn prover_index_fq_from_bytes(
    bytes: Uint8Array,
) -> NapiResult<External<WasmPastaFqPlonkIndex>> {
    let index = WasmPastaFqPlonkIndex::deserialize_inner(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e))?;
    Ok(External::new(index))
}

#[napi]
pub fn prover_index_fq_to_bytes(index: External<WasmPastaFqPlonkIndex>) -> NapiResult<Uint8Array> {
    let bytes = index
        .serialize_inner()
        .map_err(|e| Error::new(Status::GenericFailure, e))?;
    Ok(Uint8Array::from(bytes))
}

#[napi]
pub fn caml_pasta_fq_plonk_index_max_degree(index: External<WasmPastaFqPlonkIndex>) -> i32 {
    index.0.srs.max_poly_size() as i32
}

#[napi]
pub fn caml_pasta_fq_plonk_index_public_inputs(index: External<WasmPastaFqPlonkIndex>) -> i32 {
    index.0.cs.public as i32
}

#[napi]
pub fn caml_pasta_fq_plonk_index_domain_d1_size(index: External<WasmPastaFqPlonkIndex>) -> i32 {
    index.0.cs.domain.d1.size() as i32
}

#[napi]
pub fn caml_pasta_fq_plonk_index_domain_d4_size(index: External<WasmPastaFqPlonkIndex>) -> i32 {
    index.0.cs.domain.d4.size() as i32
}

#[napi]
pub fn caml_pasta_fq_plonk_index_domain_d8_size(index: External<WasmPastaFqPlonkIndex>) -> i32 {
    index.0.cs.domain.d8.size() as i32
}

#[napi]
pub fn caml_pasta_fq_plonk_index_create(
    gates: &NapiFqGateVector,
    public_: i32,
    lookup_tables: Vec<JsLookupTableFq>,
    runtime_table_cfgs: Vec<JsRuntimeTableCfgFq>,
    prev_challenges: i32,
    srs: External<WasmSrs>,
    lazy_mode: bool,
) -> Result<External<WasmPastaFqPlonkIndex>, Error> {
    // TODO: check if and how we run rayon threads automatically in napi

    let gates: Vec<_> = gates.to_vec();

    let runtime_cfgs = runtime_table_cfgs
        .into_iter()
        .map(runtime_table_cfg_fq_from_js)
        .collect::<Result<Vec<_>, _>>()?;

    let lookup_tables = lookup_tables
        .into_iter()
        .map(lookup_table_fq_from_js)
        .collect::<Result<Vec<_>, _>>()?;

    let srs_ref = srs.as_ref();

    let cs = ConstraintSystem::<Fq>::create(gates)
        .public(public_ as usize)
        .prev_challenges(prev_challenges as usize)
        .lookup(lookup_tables)
        .max_poly_size(Some(srs_ref.0.max_poly_size()))
        .runtime(if runtime_cfgs.is_empty() {
            None
        } else {
            Some(runtime_cfgs)
        })
        .lazy_mode(lazy_mode)
        .build()
        .map_err(|_| {
            Error::new(
                Status::InvalidArg,
                "caml_pasta_fq_plonk_index_create: could not create constraint system",
            )
        })?;

    let (endo_q, _endo_r) = poly_commitment::ipa::endos::<GAffineOther>();

    srs_ref.0.get_lagrange_basis(cs.domain.d1);

    let mut index = ProverIndex::<GAffine, OpeningProof<GAffine>>::create(
        cs,
        endo_q,
        srs_ref.0.clone(),
        lazy_mode,
    );
    index.compute_verifier_index_digest::<DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>>();

    Ok(External::new(WasmPastaFqPlonkIndex(Box::new(index))))
}

#[napi]
pub fn caml_pasta_fq_plonk_index_decode(
    bytes: &[u8],
    srs: External<WasmSrs>,
) -> Result<External<WasmPastaFqPlonkIndex>, Error> {
    let mut deserializer = rmp_serde::Deserializer::new(bytes);
    let mut index = ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(&mut deserializer)
        .map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("caml_pasta_fq_plonk_index_decode: {}", e),
        )
    })?;
    index.srs = srs.0.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&index.cs.feature_flags), true);
    index.linearization = linearization;
    index.powers_of_alpha = powers_of_alpha;

    Ok(External::new(WasmPastaFqPlonkIndex(Box::new(index))))
}

#[napi]
pub fn caml_pasta_fq_plonk_index_encode(
    index: External<WasmPastaFqPlonkIndex>,
) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    let mut serializer = rmp_serde::Serializer::new(&mut buffer);
    index.0.serialize(&mut serializer).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            &format!("caml_pasta_fq_plonk_index_encode: {}", e),
        )
    })?;
    Ok(buffer)
}

#[napi]
pub fn caml_pasta_fq_plonk_index_write(
    append: Option<bool>,
    index: External<WasmPastaFqPlonkIndex>,
    path: String,
) -> Result<(), Error> {
    let file = OpenOptions::new()
        .append(append.unwrap_or(true))
        .open(path)
        .map_err(|_| Error::new(Status::InvalidArg, "caml_pasta_fq_plonk_index_write"))?;
    let w = BufWriter::new(file);
    index
        .0
        .serialize(&mut rmp_serde::Serializer::new(w))
        .map_err(|e| {
            Error::new(
                Status::InvalidArg,
                &format!("caml_pasta_fq_plonk_index_write: {e}"),
            )
        })
}

#[napi]
pub fn caml_pasta_fq_plonk_index_read(
    offset: Option<i32>,
    srs: External<WasmSrs>,
    path: String,
) -> Result<External<WasmPastaFqPlonkIndex>, Error> {
    // read from file
    let file = match File::open(path) {
        Err(_) => {
            return Err(Error::new(
                Status::InvalidArg,
                "caml_pasta_fq_plonk_index_read",
            ))
        }
        Ok(file) => file,
    };
    let mut r = BufReader::new(file);

    // optional offset in file
    if let Some(offset) = offset {
        r.seek(Start(offset as u64)).map_err(|err| {
            Error::new(
                Status::InvalidArg,
                &format!("caml_pasta_fq_plonk_index_read: {err}"),
            )
        })?;
    }

    // deserialize the index
    let mut t = ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(
        &mut rmp_serde::Deserializer::new(r),
    )
    .map_err(|err| {
        Error::new(
            Status::InvalidArg,
            &format!("caml_pasta_fp_plonk_index_read: {err}"),
        )
    })?;
    t.srs = srs.0.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&t.cs.feature_flags), true);
    t.linearization = linearization;
    t.powers_of_alpha = powers_of_alpha;

    //
    Ok(External::new(WasmPastaFqPlonkIndex(Box::new(t))))
}
