use crate::WasmFpSrs;
use crate::{build_info::report_native_call, gate_vector::NapiFpGateVector};
use ark_poly::EvaluationDomain;
use kimchi::{
    circuits::{
        constraints::ConstraintSystem,
        lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    },
    linearization::expr_linearization,
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Pallas as GAffineOther, Vesta as GAffine, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use napi::bindgen_prelude::{Error, External, Status, Uint8Array};
use napi_derive::napi;
use poly_commitment::ipa::{OpeningProof, SRS as IPA_SRS};
use poly_commitment::SRS;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Cursor, Seek, SeekFrom::Start},
    sync::Arc,
};

use crate::tables::{
    lookup_table_fp_from_js, runtime_table_cfg_fp_from_js, JsLookupTableFp, JsRuntimeTableCfgFp,
};
pub struct WasmPastaFpPlonkIndex(pub Box<ProverIndex<GAffine, OpeningProof<GAffine>>>);

#[derive(Serialize, Deserialize)]
struct SerializedProverIndex {
    prover_index: Vec<u8>,
    srs: Vec<u8>,
}

impl WasmPastaFpPlonkIndex {
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
            DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        >();

        Ok(WasmPastaFpPlonkIndex(Box::new(index)))
    }
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi(js_name = "prover_index_fp_from_bytes")]
pub fn prover_index_fp_from_bytes(
    bytes: Uint8Array,
) -> napi::bindgen_prelude::Result<External<WasmPastaFpPlonkIndex>> {
    report_native_call();

    let index = WasmPastaFpPlonkIndex::deserialize_inner(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e))?;
    Ok(External::new(index))
}

// TOOD: remove incl all dependencies when no longer needed and we only pass napi objects around
#[napi(js_name = "prover_index_fp_to_bytes")]
pub fn prover_index_fp_to_bytes(
    index: &External<WasmPastaFpPlonkIndex>,
) -> napi::bindgen_prelude::Result<Uint8Array> {
    report_native_call();

    let bytes = index
        .serialize_inner()
        .map_err(|e| Error::new(Status::GenericFailure, e))?;
    Ok(Uint8Array::from(bytes))
}

#[napi(js_name = "pasta_fp_plonk_index_max_degree")]
pub fn caml_pasta_fp_plonk_index_max_degree(index: &External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.srs.max_poly_size() as i32
}

#[napi(js_name = "pasta_fp_plonk_index_public_inputs")]
pub fn caml_pasta_fp_plonk_index_public_inputs(index: &External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.public as i32
}

#[napi(js_name = "pasta_fp_plonk_index_domain_d1_size")]
pub fn caml_pasta_fp_plonk_index_domain_d1_size(index: &External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.domain.d1.size() as i32
}

#[napi(js_name = "pasta_fp_plonk_index_domain_d4_size")]
pub fn caml_pasta_fp_plonk_index_domain_d4_size(index: &External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.domain.d4.size() as i32
}

#[napi(js_name = "pasta_fp_plonk_index_domain_d8_size")]
pub fn caml_pasta_fp_plonk_index_domain_d8_size(index: &External<WasmPastaFpPlonkIndex>) -> i32 {
    index.0.cs.domain.d8.size() as i32
}

#[napi(js_name = "pasta_fp_plonk_index_create")]
pub fn caml_pasta_fp_plonk_index_create(
    gates: &NapiFpGateVector,
    public_: i32,
    lookup_tables: Vec<JsLookupTableFp>,
    runtime_table_cfgs: Vec<JsRuntimeTableCfgFp>,
    prev_challenges: i32,
    srs: &External<WasmFpSrs>,
    lazy_mode: bool,
) -> Result<External<WasmPastaFpPlonkIndex>, Error> {
    let gates: Vec<_> = gates.to_vec();

    let runtime_cfgs: Vec<RuntimeTableCfg<Fp>> = runtime_table_cfgs
        .into_iter()
        .map(runtime_table_cfg_fp_from_js)
        .collect::<Result<_, _>>()?;

    let lookup_tables: Vec<LookupTable<Fp>> = lookup_tables
        .into_iter()
        .map(lookup_table_fp_from_js)
        .collect::<Result<_, _>>()?;

    let srs_ref = srs.as_ref();

    let cs = ConstraintSystem::<Fp>::create(gates)
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
                "caml_pasta_fp_plonk_index_create: could not create constraint system",
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
    index.compute_verifier_index_digest::<DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>();

    Ok(External::new(WasmPastaFpPlonkIndex(Box::new(index))))
}

#[napi(js_name = "pasta_fp_plonk_index_decode")]
pub fn caml_pasta_fp_plonk_index_decode(
    bytes: &[u8],
    srs: &External<WasmFpSrs>,
) -> Result<External<WasmPastaFpPlonkIndex>, Error> {
    let mut deserializer = rmp_serde::Deserializer::new(bytes);
    let mut index = ProverIndex::<GAffine, OpeningProof<GAffine>>::deserialize(&mut deserializer)
        .map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("caml_pasta_fp_plonk_index_decode: {}", e),
        )
    })?;

    index.srs = srs.0.clone();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&index.cs.feature_flags), true);
    index.linearization = linearization;
    index.powers_of_alpha = powers_of_alpha;

    Ok(External::new(WasmPastaFpPlonkIndex(Box::new(index))))
}

#[napi(js_name = "pasta_fp_plonk_index_encode")]
pub fn caml_pasta_fp_plonk_index_encode(
    index: &External<WasmPastaFpPlonkIndex>,
) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    let mut serializer = rmp_serde::Serializer::new(&mut buffer);
    index.0.serialize(&mut serializer).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            &format!("caml_pasta_fp_plonk_index_encode: {}", e),
        )
    })?;
    Ok(buffer)
}

#[napi(js_name = "pasta_fp_plonk_index_write")]
pub fn caml_pasta_fp_plonk_index_write(
    append: Option<bool>,
    index: &External<WasmPastaFpPlonkIndex>,
    path: String,
) -> Result<(), Error> {
    let file = OpenOptions::new()
        .append(append.unwrap_or(true))
        .open(path)
        .map_err(|_| Error::new(Status::InvalidArg, "caml_pasta_fp_plonk_index_write"))?;
    let w = BufWriter::new(file);
    index
        .0
        .serialize(&mut rmp_serde::Serializer::new(w))
        .map_err(|e| {
            Error::new(
                Status::InvalidArg,
                &format!("caml_pasta_fp_plonk_index_write: {e}"),
            )
        })
}

#[napi(js_name = "pasta_fp_plonk_index_read")]
pub fn caml_pasta_fp_plonk_index_read(
    offset: Option<i32>,
    srs: &External<WasmFpSrs>,
    path: String,
) -> Result<External<WasmPastaFpPlonkIndex>, Error> {
    // read from file
    let file = match File::open(path) {
        Err(_) => {
            return Err(Error::new(
                Status::InvalidArg,
                "caml_pasta_fp_plonk_index_read",
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
                &format!("caml_pasta_fp_plonk_index_read: {err}"),
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
    Ok(External::new(WasmPastaFpPlonkIndex(Box::new(t))))
}
