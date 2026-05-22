//! Deterministic RNG for kimchi proof creation.
//!
//! Sister module to the OCaml-side `kimchi-stubs/src/deterministic_rng.rs`
//! (and the former PureScript `crypto-provider` helper). Both wrappers around
//! the kimchi prover seed the SAME `ChaCha20Rng` from the same env var so that
//! `ProverProof::create` draws identical blinder bytes on every side — required
//! for the byte-identical witness/trace reproduction tests. The napi prover
//! previously used `OsRng` here, which made every proof's blinders (and hence
//! commitments) non-deterministic, breaking those parity tests downstream
//! (e.g. a wrap proof verifying a step proof absorbs its commitments).
//!
//! If `KIMCHI_DETERMINISTIC_SEED` is unset, we default to `DEFAULT_SEED`
//! (= 42) so proofs are reproducible out of the box. Setting the env var to an
//! explicit value overrides. An *unparseable* value is fatal — the user tried
//! to set it, we refuse to silently ignore typos. We intentionally do NOT fall
//! back to `OsRng` under any path; silent non-determinism is the problem this
//! module exists to eliminate.

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

const SEED_ENV_VAR: &str = "KIMCHI_DETERMINISTIC_SEED";

/// Default seed when `KIMCHI_DETERMINISTIC_SEED` is unset. Kept in sync with
/// the OCaml-side kimchi-stubs helper so both sides produce identical proofs
/// without requiring the caller to set the env var.
const DEFAULT_SEED: u64 = 42;

/// Build a fresh `ChaCha20Rng` seeded from `KIMCHI_DETERMINISTIC_SEED` (or
/// `DEFAULT_SEED` when the env var is unset). Each call returns an
/// independently-seeded RNG with the SAME starting state, matching the
/// OCaml-side helper bit-for-bit.
///
/// Uses `eprintln!` + `std::process::exit(1)` rather than `panic!` on an
/// unparseable value: this crate is loaded as a Node native addon (napi-rs),
/// and unwinding a Rust panic across the C FFI boundary is undefined behavior.
pub fn make_rng() -> ChaCha20Rng {
    let seed = match std::env::var(SEED_ENV_VAR) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(seed) => seed,
            Err(e) => {
                eprintln!(
                    "[kimchi-napi] FATAL: {SEED_ENV_VAR} must parse as u64, \
                     got `{raw}`: {e}"
                );
                std::process::exit(1);
            }
        },
        Err(_) => DEFAULT_SEED,
    };
    ChaCha20Rng::seed_from_u64(seed)
}
