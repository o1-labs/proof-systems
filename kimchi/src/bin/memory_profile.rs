//! End-to-end prover memory profile.
//!
//! Proves either the canonical benchmark circuit (`kimchi::bench::BenchmarkCtx`)
//! or a serialised mina circuit fixture (the same `kimchi_inputs_*.ser` files
//! the `proof_criterion_mina` bench consumes) under a counting global
//! allocator and reports, for the proof-creation window: total bytes
//! allocated, allocation count, peak live bytes (and its delta over the bytes
//! live when the window opened), plus jemalloc's peak resident set sampled by
//! a background thread. The process exists for this one measurement, so the
//! counters are exact for a deterministic workload — a single run is the
//! answer.
//!
//! Usage:
//!
//! ```text
//! cargo run --release -p kimchi --bin memory_profile --features diagnostics -- synthetic [--srs-log2 16]
//! cargo run --release -p kimchi --bin memory_profile --features diagnostics -- fixture <kimchi_inputs_CURVE_SEED.ser>
//! ```
//!
//! `synthetic` proves the benchmark circuit at the given domain/SRS size;
//! `fixture` proves a mina fixture, whose curve and seed are parsed from the
//! filename exactly as in `proof_criterion_mina`. Output is a single JSON
//! object on stdout (byte counts, not MB), meant to be collected across
//! fixtures and diffed against a baseline run — see
//! `scripts/memory-profile-mina-circuits.sh` and
//! `scripts/memory-profile-diff.py`.
//! One fixture per invocation: jemalloc retains pages across proofs, so
//! `peak_resident` is only trustworthy for the first proof in a process.
//! The resident-set sampler interval is `KIMCHI_MEMORY_PROFILE_SAMPLE_MS`
//! (default 25).

use ark_ff::PrimeField;
use clap::Parser;
use groupmap::GroupMap;
use kimchi::{
    bench::{
        bench_arguments_from_file, BaseSpongePallas, BaseSpongeVesta, BenchmarkCtx,
        ScalarSpongePallas, ScalarSpongeVesta,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    proof::ProverProof,
};
use mina_curves::{
    named::NamedCurve,
    pasta::{Pallas, Vesta},
};
use mina_poseidon::{pasta::FULL_ROUNDS, FqSponge};
use poly_commitment::ipa::OpeningProof;
use std::time::Instant;

// A counting wrapper around jemalloc. jemalloc-ctl statistics still observe
// the real allocator, while the counters capture what jemalloc cannot report
// over a window: total bytes allocated, allocation count, and peak live
// bytes. Counting is unconditional: this binary is the measurement.
mod counting_alloc {
    use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use std::alloc::{GlobalAlloc, Layout};
    use tikv_jemallocator::Jemalloc;

    pub static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
    pub static COUNT: AtomicUsize = AtomicUsize::new(0);
    pub static CURRENT: AtomicUsize = AtomicUsize::new(0);
    pub static PEAK: AtomicUsize = AtomicUsize::new(0);

    fn record_alloc(size: usize) {
        ALLOCATED.fetch_add(size, Relaxed);
        COUNT.fetch_add(1, Relaxed);
        let live = CURRENT.fetch_add(size, Relaxed) + size;
        PEAK.fetch_max(live, Relaxed);
    }

    struct CountingAlloc;

    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = Jemalloc.alloc(layout);
            if !p.is_null() {
                record_alloc(layout.size());
            }
            p
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let p = Jemalloc.alloc_zeroed(layout);
            if !p.is_null() {
                record_alloc(layout.size());
            }
            p
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let p = Jemalloc.realloc(ptr, layout, new_size);
            if !p.is_null() {
                CURRENT.fetch_sub(layout.size(), Relaxed);
                record_alloc(new_size);
            }
            p
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            CURRENT.fetch_sub(layout.size(), Relaxed);
            Jemalloc.dealloc(ptr, layout)
        }
    }

    #[global_allocator]
    static GLOBAL: CountingAlloc = CountingAlloc;
}

/// An allocation profile over a window of execution.
mod mem_profile {
    use super::counting_alloc::{ALLOCATED, COUNT, CURRENT, PEAK};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

    static STOP: AtomicBool = AtomicBool::new(false);
    static PEAK_RESIDENT: AtomicUsize = AtomicUsize::new(0);

    pub struct Window {
        live_before: usize,
        sampler: std::thread::JoinHandle<()>,
    }

    pub fn start() -> Window {
        let sample_ms: u64 = match std::env::var("KIMCHI_MEMORY_PROFILE_SAMPLE_MS") {
            Err(_) => 25,
            Ok(s) => s.parse().ok().filter(|ms| *ms >= 1).unwrap_or_else(|| {
                panic!("KIMCHI_MEMORY_PROFILE_SAMPLE_MS must be a positive integer (ms), got {s:?}")
            }),
        };
        let sampler = std::thread::spawn(move || {
            use tikv_jemalloc_ctl::{epoch, stats};
            while !STOP.load(Relaxed) {
                if epoch::advance().is_ok() {
                    if let Ok(r) = stats::resident::read() {
                        PEAK_RESIDENT.fetch_max(r, Relaxed);
                    }
                }
                std::thread::sleep(core::time::Duration::from_millis(sample_ms));
            }
        });

        // Reset the window counters after spawning the sampler, so the
        // spawn's own allocations stay out of the profile.
        let live_before = CURRENT.load(Relaxed);
        ALLOCATED.store(0, Relaxed);
        COUNT.store(0, Relaxed);
        PEAK.store(live_before, Relaxed);
        Window {
            live_before,
            sampler,
        }
    }

    #[derive(serde::Serialize)]
    pub struct Metrics {
        #[serde(rename = "allocated_bytes")]
        pub allocated: usize,
        pub allocs: usize,
        #[serde(rename = "peak_live_bytes")]
        pub peak_live: usize,
        #[serde(rename = "peak_delta_bytes")]
        pub peak_delta: usize,
        #[serde(rename = "peak_resident_bytes")]
        pub peak_resident: usize,
    }

    impl Window {
        pub fn finish(self) -> Metrics {
            STOP.store(true, Relaxed);
            let _ = self.sampler.join();
            let peak_live = PEAK.load(Relaxed);
            Metrics {
                allocated: ALLOCATED.load(Relaxed),
                allocs: COUNT.load(Relaxed),
                peak_live,
                peak_delta: peak_live.saturating_sub(self.live_before),
                peak_resident: PEAK_RESIDENT.load(Relaxed),
            }
        }
    }
}

/// One profiled proof, as the JSON object written to stdout.
#[derive(serde::Serialize)]
struct Report<'a> {
    workload: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    srs_log2: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    curve: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_log2: Option<u32>,
    setup_ms: u128,
    prove_ms: u128,
    #[serde(flatten)]
    metrics: mem_profile::Metrics,
}

impl std::fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&serde_json::to_string(self).map_err(|_| std::fmt::Error)?)
    }
}

/// A serialised mina circuit fixture, addressed by the filename convention
/// `kimchi_inputs_CURVE_SEED.ser` that `proof_criterion_mina` also uses.
#[derive(Clone)]
struct Fixture {
    path: String,
    curve: String,
    seed: String,
}

impl std::str::FromStr for Fixture {
    type Err = String;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let (curve, seed) = path
            .split('/')
            .next_back()
            .unwrap_or(path)
            .strip_prefix("kimchi_inputs_")
            .and_then(|s| s.strip_suffix(".ser"))
            .and_then(|s| s.split_once('_'))
            .ok_or_else(|| {
                format!(
                    "fixture filename must look like kimchi_inputs_CURVE_SEED.ser, got {path:?}"
                )
            })?;
        Ok(Fixture {
            path: path.to_string(),
            curve: curve.to_string(),
            seed: seed.to_string(),
        })
    }
}

fn profile_synthetic(srs_log2: u32) {
    let setup_start = Instant::now();
    let ctx = BenchmarkCtx::new(srs_log2);
    let setup_ms = setup_start.elapsed().as_millis();

    let window = mem_profile::start();
    let prove_start = Instant::now();
    let proof_and_public = ctx.create_proof();
    let prove_ms = prove_start.elapsed().as_millis();
    let metrics = window.finish();
    std::hint::black_box(proof_and_public);

    println!(
        "{}",
        Report {
            workload: "synthetic",
            srs_log2: Some(srs_log2),
            curve: None,
            seed: None,
            domain_log2: None,
            setup_ms,
            prove_ms,
            metrics,
        }
    );
}

fn profile_fixture_curve<G, BaseSponge, ScalarSponge>(fixture: &Fixture)
where
    G: KimchiCurve<FULL_ROUNDS> + NamedCurve,
    G::BaseField: PrimeField,
    BaseSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
    ScalarSponge: FrSponge<G::ScalarField>
        + From<&'static mina_poseidon::poseidon::ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
{
    let setup_start = Instant::now();
    let srs = poly_commitment::precomputed_srs::get_srs_test();
    let (index, witness, runtime_tables, prev) =
        bench_arguments_from_file::<FULL_ROUNDS, G, BaseSponge>(srs, fixture.path.clone());
    let group_map = GroupMap::<_>::setup();
    let domain_log2 = index.cs.domain.d1.size.trailing_zeros();
    let setup_ms = setup_start.elapsed().as_millis();

    let window = mem_profile::start();
    let prove_start = Instant::now();
    let proof = ProverProof::<G, OpeningProof<G, FULL_ROUNDS>, FULL_ROUNDS>::create_recursive::<
        BaseSponge,
        ScalarSponge,
        _,
    >(
        &group_map,
        witness,
        &runtime_tables,
        &index,
        prev,
        None,
        &mut rand::rngs::OsRng,
    )
    .expect("proof creation failed: the fixture no longer satisfies the constraint system");
    let prove_ms = prove_start.elapsed().as_millis();
    let metrics = window.finish();
    std::hint::black_box(proof);

    println!(
        "{}",
        Report {
            workload: "fixture",
            srs_log2: None,
            curve: Some(&fixture.curve),
            seed: Some(&fixture.seed),
            domain_log2: Some(domain_log2),
            setup_ms,
            prove_ms,
            metrics,
        }
    );
}

fn profile_mina_fixture(fixture: &Fixture) {
    if fixture.curve == Vesta::NAME {
        profile_fixture_curve::<Vesta, BaseSpongeVesta, ScalarSpongeVesta>(fixture);
    } else if fixture.curve == Pallas::NAME {
        profile_fixture_curve::<Pallas, BaseSpongePallas, ScalarSpongePallas>(fixture);
    } else {
        panic!("Unsupported curve: {}", fixture.curve);
    }
}

#[derive(Parser)]
#[command(about = "End-to-end prover memory profile; emits one JSON object on stdout")]
enum Cli {
    /// Prove the synthetic benchmark circuit (kimchi::bench::BenchmarkCtx)
    Synthetic {
        /// log2 of the domain/SRS size
        #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(4..=28))]
        srs_log2: u32,
    },
    /// Prove a serialised mina circuit fixture (kimchi_inputs_CURVE_SEED.ser)
    Fixture { fixture: Fixture },
}

fn main() {
    match Cli::parse() {
        Cli::Synthetic { srs_log2 } => profile_synthetic(srs_log2),
        Cli::Fixture { fixture } => profile_mina_fixture(&fixture),
    }
}
