//! Deterministic RNG for kimchi proof creation.
//!
//! Replaces `OsRng` at the kimchi-stubs FFI boundary with a `ChaCha20Rng`
//! seeded from the `KIMCHI_DETERMINISTIC_SEED` environment variable. Required
//! for the PureScript-side reproduction tests, which compare bit-identical
//! traces against an OCaml fixture run.
//!
//! If `KIMCHI_DETERMINISTIC_SEED` is unset, we default to `DEFAULT_SEED`
//! (= 42) on both sides so proofs are reproducible out of the box. Setting
//! the env var to an explicit value overrides. An *unparseable* value is
//! still fatal — the user tried to set it, we refuse to silently ignore
//! typos. We intentionally do NOT fall back to `OsRng` under any path;
//! silent non-determinism is the problem this module exists to eliminate.
//! If you're running mina or kimchi-stubs in production, set the env var
//! to a fixed value (or any value) before launch.

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

const SEED_ENV_VAR: &str = "KIMCHI_DETERMINISTIC_SEED";

/// Default seed when `KIMCHI_DETERMINISTIC_SEED` is unset. Kept in sync
/// with the PureScript-side crypto-provider helper so both sides produce
/// identical proofs without requiring the caller to set the env var.
const DEFAULT_SEED: u64 = 42;

/// Build a fresh `ChaCha20Rng` seeded from `KIMCHI_DETERMINISTIC_SEED`
/// (or `DEFAULT_SEED` when the env var is unset).
///
/// Each call returns an independently-seeded RNG with the SAME starting
/// state, so consecutive proof creations begin from the same RNG draws.
/// This matches the PureScript-side helper bit-for-bit.
///
/// Calls `eprintln!` + `std::process::exit(1)` rather than `panic!` when
/// the env var is set to an unparseable value: kimchi-stubs is loaded as
/// a static library by OCaml (mina) and as a cdylib by Node (PureScript
/// napi-rs), and a Rust panic unwinding across the C FFI boundary is
/// undefined behavior — in practice it produces a SIGSEGV with a
/// stack-smashing abort message that completely buries our error
/// message. `exit(1)` terminates the process cleanly with a visible
/// diagnostic.
pub fn make_rng() -> ChaCha20Rng {
    let seed = match std::env::var(SEED_ENV_VAR) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(seed) => seed,
            Err(e) => {
                eprintln!(
                    "[kimchi-stubs] FATAL: {SEED_ENV_VAR} must parse as u64, \
                     got `{raw}`: {e}"
                );
                std::process::exit(1);
            }
        },
        Err(_) => DEFAULT_SEED,
    };
    ChaCha20Rng::seed_from_u64(seed)
}
