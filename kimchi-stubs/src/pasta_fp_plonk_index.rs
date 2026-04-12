use crate::{arkworks::CamlFp, gate_vector::fp::CamlPastaFpPlonkGateVectorPtr, srs::fp::CamlFpSrs};
use ark_poly::EvaluationDomain;
use kimchi::{
    cached_prover_index::MmapProverIndex,
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        lookup::{
            runtime_tables::{caml::CamlRuntimeTableCfg, RuntimeTableCfg},
            tables::{caml::CamlLookupTable, LookupTable},
        },
    },
    linearization::expr_linearization,
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Pallas, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi, pasta::FULL_ROUNDS, sponge::DefaultFqSponge,
};
use poly_commitment::{ipa::OpeningProof, lagrange_basis::WithLagrangeBasis, SRS as _};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom::Start},
};

type Srs =
    <OpeningProof<Vesta, FULL_ROUNDS> as poly_commitment::OpenProof<Vesta, FULL_ROUNDS>>::SRS;

/// Holds a prover index behind one of two backing stores. The enum
/// variants both [`Deref`] to the same `&ProverIndex`, so all existing
/// `.0.cs…` / `.0.srs…` field-access patterns in this file continue to
/// work via auto-deref. Concretely:
///
/// - [`IndexHandle::Owned`] is the classic path: a heap-allocated
///   `ProverIndex` whose `Vec<F>` fields are Rust-owned. Populated by
///   `caml_pasta_fp_plonk_index_create` / `_read`.
/// - [`IndexHandle::Mmap`] wraps an [`MmapProverIndex`] whose bulk
///   `Vec<F>` fields point into an mmap'd cache file. Populated by
///   `caml_pasta_fp_plonk_index_read_cached`. Dropping an `Mmap` variant
///   skips the inner `Vec<F>`s' destructors (they would otherwise call
///   `dealloc` on mmap memory — UB) and unmaps the file.
pub enum IndexHandle {
    Owned(Box<ProverIndex<FULL_ROUNDS, Vesta, Srs>>),
    Mmap(Box<MmapProverIndex<FULL_ROUNDS, Vesta, Srs>>),
}

impl core::ops::Deref for IndexHandle {
    type Target = ProverIndex<FULL_ROUNDS, Vesta, Srs>;
    fn deref(&self) -> &Self::Target {
        match self {
            IndexHandle::Owned(b) => b,
            IndexHandle::Mmap(b) => b,
        }
    }
}

/// Boxed so that we don't store large proving indexes in the OCaml heap.
#[derive(ocaml_gen::CustomType)]
pub struct CamlPastaFpPlonkIndex(pub IndexHandle);
pub type CamlPastaFpPlonkIndexPtr<'a> = ocaml::Pointer<'a, CamlPastaFpPlonkIndex>;

extern "C" fn caml_pasta_fp_plonk_index_finalize(v: ocaml::Raw) {
    unsafe {
        let mut v: CamlPastaFpPlonkIndexPtr = v.as_pointer();
        v.as_mut_ptr().drop_in_place();
    }
}

impl ocaml::custom::Custom for CamlPastaFpPlonkIndex {
    const NAME: &'static str = "CamlPastaFpPlonkIndex\0";
    const USED: usize = 1;
    /// Encourage the GC to free when there are > 12 in memory
    const MAX: usize = 12;
    const OPS: ocaml::custom::CustomOps = ocaml::custom::CustomOps {
        identifier: Self::NAME.as_ptr() as *const ocaml::sys::Char,
        finalize: Some(caml_pasta_fp_plonk_index_finalize),
        ..ocaml::custom::DEFAULT_CUSTOM_OPS
    };
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_create(
    gates: CamlPastaFpPlonkGateVectorPtr,
    public: ocaml::Int,
    lookup_tables: Vec<CamlLookupTable<CamlFp>>,
    runtime_tables: Vec<CamlRuntimeTableCfg<CamlFp>>,
    prev_challenges: ocaml::Int,
    srs: CamlFpSrs,
    lazy_mode: bool,
) -> Result<CamlPastaFpPlonkIndex, ocaml::Error> {
    let gates: Vec<_> = gates
        .as_ref()
        .0
        .iter()
        .map(|gate| CircuitGate::<Fp> {
            typ: gate.typ,
            wires: gate.wires,
            coeffs: gate.coeffs.clone(),
        })
        .collect();

    let runtime_tables: Vec<RuntimeTableCfg<Fp>> =
        runtime_tables.into_iter().map(Into::into).collect();

    let lookup_tables: Vec<LookupTable<Fp>> = lookup_tables.into_iter().map(Into::into).collect();

    // create constraint system
    let cs = ConstraintSystem::<Fp>::create(gates)
        .public(public as usize)
        .prev_challenges(prev_challenges as usize)
        .max_poly_size(Some(srs.0.max_poly_size()))
        .lookup(lookup_tables)
        .runtime(if runtime_tables.is_empty() {
            None
        } else {
            Some(runtime_tables)
        })
        .lazy_mode(lazy_mode)
        .build()?;

    // endo
    let (endo_q, _endo_r) = poly_commitment::ipa::endos::<Pallas>();

    srs.0.with_lagrange_basis(cs.domain.d1);

    // create index
    let mut index = ProverIndex::create(cs, endo_q, srs.clone(), lazy_mode);
    // Compute and cache the verifier index digest
    index.compute_verifier_index_digest::<DefaultFqSponge<
        VestaParameters,
        PlonkSpongeConstantsKimchi,
        FULL_ROUNDS,
    >>();

    Ok(CamlPastaFpPlonkIndex(IndexHandle::Owned(Box::new(index))))
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_max_degree(index: CamlPastaFpPlonkIndexPtr) -> ocaml::Int {
    index.as_ref().0.srs.max_poly_size() as isize
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_public_inputs(index: CamlPastaFpPlonkIndexPtr) -> ocaml::Int {
    index.as_ref().0.cs.public as isize
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_domain_d1_size(index: CamlPastaFpPlonkIndexPtr) -> ocaml::Int {
    index.as_ref().0.cs.domain.d1.size() as isize
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_domain_d4_size(index: CamlPastaFpPlonkIndexPtr) -> ocaml::Int {
    index.as_ref().0.cs.domain.d4.size() as isize
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_domain_d8_size(index: CamlPastaFpPlonkIndexPtr) -> ocaml::Int {
    index.as_ref().0.cs.domain.d8.size() as isize
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_read(
    offset: Option<ocaml::Int>,
    srs: CamlFpSrs,
    path: String,
) -> Result<CamlPastaFpPlonkIndex, ocaml::Error> {
    // open the file for reading
    let file = match File::open(path) {
        Err(_) => {
            return Err(
                ocaml::Error::invalid_argument("caml_pasta_fp_plonk_index_read")
                    .err()
                    .unwrap(),
            )
        }
        Ok(file) => file,
    };
    let mut r = BufReader::new(file);

    // optional offset in file
    if let Some(offset) = offset {
        r.seek(Start(offset as u64))?;
    }

    // deserialize the index
    let mut t =
        ProverIndex::<FULL_ROUNDS, Vesta, Srs>::deserialize(&mut rmp_serde::Deserializer::new(r))?;
    t.srs = srs.clone();

    let (linearization, powers_of_alpha) = expr_linearization(Some(&t.cs.feature_flags), true);
    t.linearization = linearization;
    t.powers_of_alpha = powers_of_alpha;

    Ok(CamlPastaFpPlonkIndex(IndexHandle::Owned(Box::new(t))))
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_write(
    append: Option<bool>,
    index: CamlPastaFpPlonkIndexPtr<'static>,
    path: String,
) -> Result<(), ocaml::Error> {
    let file = OpenOptions::new()
        .append(append.unwrap_or(true))
        .open(path)
        .map_err(|_| {
            ocaml::Error::invalid_argument("caml_pasta_fp_plonk_index_write")
                .err()
                .unwrap()
        })?;
    let w = BufWriter::new(file);
    // Legacy rmp_serde write only supports the fully-owned `ProverIndex`
    // backing; serialising an mmap-backed index would require copying
    // every Vec<F> back through serde, which defeats its purpose.
    match &index.as_ref().0 {
        IndexHandle::Owned(b) => b
            .serialize(&mut rmp_serde::Serializer::new(w))
            .map_err(|e| e.into()),
        IndexHandle::Mmap(_) => Err(ocaml::Error::Message(
            "caml_pasta_fp_plonk_index_write: legacy serde write is not \
             supported for mmap-backed indexes; use \
             caml_pasta_fp_plonk_index_write_cached instead",
        )),
    }
}

/// Writes the proving index to `path` in the mmap-backed cache format.
///
/// `identifier` is a caller-supplied string (bounded at 512 bytes) that is
/// round-tripped through the file header. Reads must pass the same
/// identifier; mismatches return a descriptive error instead of loading
/// the wrong key.
///
/// Writes are atomic: the file is staged at `path.tmp` then renamed into
/// place so concurrent readers never observe a half-written file.
#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_write_cached(
    identifier: String,
    index: CamlPastaFpPlonkIndexPtr<'static>,
    path: String,
) -> Result<(), ocaml::Error> {
    // Both `IndexHandle` variants Deref to `&ProverIndex`, which is what
    // `write_cache` consumes; a double-borrow (`&*`) forces the coercion.
    kimchi::cached_prover_index::write_cache(
        &identifier,
        &*index.as_ref().0,
        std::path::Path::new(&path),
    )
    .map_err(|e| {
        ocaml::Error::Message(Box::leak(
            format!("caml_pasta_fp_plonk_index_write_cached: {e}").into_boxed_str(),
        ))
    })
}

/// Reads a proving index from `path` in the mmap-backed cache format,
/// binding the supplied `srs` onto the reconstructed index.
///
/// `identifier` must match the value used at write time or the call fails
/// without loading the key.
#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_pasta_fp_plonk_index_read_cached(
    identifier: String,
    srs: CamlFpSrs,
    path: String,
) -> Result<CamlPastaFpPlonkIndex, ocaml::Error> {
    let index = kimchi::cached_prover_index::read_cache::<FULL_ROUNDS, Vesta, Srs>(
        &identifier,
        std::path::Path::new(&path),
        srs.clone(),
    )
    .map_err(|e| {
        ocaml::Error::Message(Box::leak(
            format!("caml_pasta_fp_plonk_index_read_cached: {e}").into_boxed_str(),
        ))
    })?;
    Ok(CamlPastaFpPlonkIndex(IndexHandle::Mmap(Box::new(index))))
}
