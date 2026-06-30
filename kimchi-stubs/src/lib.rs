//! The Marlin_plonk_stubs crate exports some functionalities
//! and structures from the following the Rust crates to OCaml:
//!
//! * [Proof-systems](https://github.com/o1-labs/proof-systems),
//!   a PLONK implementation.
//! * [Arkworks](http://arkworks.rs/),
//!   a math library that Proof-systems builds on top of.
//!

// Allow lints from ocaml derive macros until upstream crates are updated.
// See https://github.com/o1-labs/mina-rust/issues/1954
#![allow(non_local_definitions)]
#![allow(unexpected_cfgs)]

extern crate libc;

/// Caml helpers
#[macro_use]
pub mod caml;

/// Arkworks types
pub mod arkworks;

/// Utils
pub mod urs_utils; // TODO: move this logic to proof-systems

/// Error plumbing for the cached-index FFI wrappers
pub mod cache_error;

/// Vectors
pub mod field_vector;
pub mod gate_vector;

/// Curves
pub mod projective;

/// SRS
pub mod srs;

/// Indexes
pub mod pasta_fp_plonk_index;
pub mod pasta_fq_plonk_index;

/// Verifier indexes/keys
pub mod plonk_verifier_index;

pub mod pasta_fp_plonk_verifier_index;
pub mod pasta_fq_plonk_verifier_index;

/// Oracles
pub mod oracles;

/// Proofs
pub mod pasta_fp_plonk_proof;
pub mod pasta_fq_plonk_proof;

/// Poseidon
pub mod pasta_fp_poseidon;
pub mod pasta_fq_poseidon;

/// Linearization helpers
pub mod linearization;

/// Handy re-exports
pub use {
    kimchi::circuits::{
        gate::{caml::CamlCircuitGate, CurrOrNext, GateType},
        scalars::caml::CamlRandomOracles,
        wires::caml::CamlWire,
    },
    kimchi::proof::caml::CamlProofEvaluations,
    kimchi::prover::caml::{
        CamlLookupCommitments, CamlProofWithPublic, CamlProverCommitments, CamlProverProof,
    },
    mina_poseidon::sponge::caml::CamlScalarChallenge,
    poly_commitment::{commitment::caml::CamlPolyComm, ipa::caml::CamlOpeningProof},
};

/// Per-thread-count freelist of warm rayon pools, reused across proves so a
/// long-running worker does not pay thread-spawn + cold-cache cost on every
/// compression proof.
fn prove_pool_cache() -> &'static std::sync::Mutex<
    std::collections::HashMap<usize, Vec<std::sync::Arc<rayon::ThreadPool>>>,
> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, Vec<std::sync::Arc<rayon::ThreadPool>>>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Run a proving closure in a scoped rayon thread pool sized by
/// `KIMCHI_PROVE_THREADS`, falling back to the global pool when unset. Lets a
/// long-running worker prove different tasks at different thread counts -- e.g.
/// low rayon for the many parallel base proofs, high rayon for the
/// low-concurrency compression proofs -- without rebuilding its global pool.
///
/// The thread count does not affect the proof, so this is VK-preserving.
///
/// Pools are checked out of a per-N freelist and returned after use: warm
/// threads are reused, but concurrent proves of the same N each get their own
/// pool (the freelist grows to the peak concurrency for that N), so parallelism
/// is preserved.
pub(crate) fn with_prove_pool<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    let n = match std::env::var("KIMCHI_PROVE_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        Some(n) if n >= 1 => n,
        _ => return f(),
    };
    let pool = {
        let mut cache = prove_pool_cache().lock().unwrap();
        cache
            .get_mut(&n)
            .and_then(|free| free.pop())
            .unwrap_or_else(|| {
                std::sync::Arc::new(
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(n)
                        .build()
                        .expect("KIMCHI_PROVE_THREADS thread pool"),
                )
            })
    };
    let result = pool.install(f);
    prove_pool_cache()
        .lock()
        .unwrap()
        .entry(n)
        .or_default()
        .push(pool);
    result
}
