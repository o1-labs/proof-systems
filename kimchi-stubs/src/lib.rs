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

/// Run a proving closure in a scoped rayon thread pool sized by
/// `KIMCHI_PROVE_THREADS`, falling back to the global pool when unset. Lets a
/// long-running worker prove different tasks at different thread counts -- e.g.
/// low rayon for the many parallel base proofs, high rayon for the
/// low-concurrency compression proofs -- without rebuilding its global pool.
///
/// The thread count does not affect the proof, so this is VK-preserving.
pub(crate) fn with_prove_pool<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    match std::env::var("KIMCHI_PROVE_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        Some(n) if n >= 1 => rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build()
            .expect("KIMCHI_PROVE_THREADS thread pool")
            .install(f),
        _ => f(),
    }
}
