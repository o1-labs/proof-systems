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
//! cargo run --release -p kimchi --bin memory_profile --features diagnostics -- [srs_log2]
//! cargo run --release -p kimchi --bin memory_profile --features diagnostics -- <kimchi_inputs_CURVE_SEED.ser>
//! ```
//!
//! An integer argument selects the synthetic benchmark circuit and sets its
//! domain/SRS size (default 16); a path selects a mina fixture, whose curve
//! and seed are parsed from the filename exactly as in `proof_criterion_mina`.
//! One fixture per invocation: jemalloc retains pages across proofs, so
//! `peak_resident` is only trustworthy for the first proof in a process.
//! The resident-set sampler interval is `KIMCHI_MEMORY_PROFILE_SAMPLE_MS`
//! (default 25).

use groupmap::GroupMap;
use kimchi::{
    bench::{
        bench_arguments_from_file, BaseSpongePallas, BaseSpongeVesta, BenchmarkCtx,
        ScalarSpongePallas, ScalarSpongeVesta,
    },
    proof::ProverProof,
};
use mina_curves::{
    named::NamedCurve,
    pasta::{Pallas, Vesta},
};
use mina_poseidon::pasta::FULL_ROUNDS;
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

    impl Window {
        pub fn report(self, label: &str) {
            STOP.store(true, Relaxed);
            let _ = self.sampler.join();
            let mb = |b: usize| b as f64 / (1u64 << 20) as f64;
            println!(
                "- {label} allocation profile: allocated={:.1} MB allocs={} \
                 peak_live={:.1} MB peak_delta={:.1} MB peak_resident={:.1} MB",
                mb(ALLOCATED.load(Relaxed)),
                COUNT.load(Relaxed),
                mb(PEAK.load(Relaxed)),
                mb(PEAK.load(Relaxed).saturating_sub(self.live_before)),
                mb(PEAK_RESIDENT.load(Relaxed)),
            );
        }
    }
}

fn profile_synthetic(srs_log2: u32) {
    assert!(
        (4..=28).contains(&srs_log2),
        "srs_log2 must be in 4..=28, got {srs_log2}"
    );
    println!("PROVER MEMORY PROFILE: domain/SRS 2^{srs_log2}");

    let setup_start = Instant::now();
    let ctx = BenchmarkCtx::new(srs_log2);
    println!(
        "- setup time (index, verifier digest, lagrange basis): {} ms",
        setup_start.elapsed().as_millis()
    );

    let window = mem_profile::start();
    let prove_start = Instant::now();
    let proof_and_public = ctx.create_proof();
    let prove_time = prove_start.elapsed();
    window.report("proof creation");
    println!("- time to create proof: {} ms", prove_time.as_millis());

    std::hint::black_box(proof_and_public);
}

fn profile_mina_fixture(filename: &str) {
    // Parse filename "kimchi_inputs_CURVENAME_SEED.ser" into two parameters,
    // exactly as `proof_criterion_mina` does.
    let (curve_name, seed): (&str, &str) = filename
        .split('/')
        .next_back()
        .unwrap()
        .strip_prefix("kimchi_inputs_")
        .and_then(|s| s.strip_suffix(".ser"))
        .and_then(|s| s.split_once('_'))
        .unwrap_or_else(|| {
            panic!("fixture filename must look like kimchi_inputs_CURVE_SEED.ser, got {filename:?}")
        });

    macro_rules! profile_curve {
        ($G:ty, $BaseSponge:ty, $ScalarSponge:ty) => {{
            let setup_start = Instant::now();
            let srs = poly_commitment::precomputed_srs::get_srs_test();
            let (index, witness, runtime_tables, prev) =
                bench_arguments_from_file::<FULL_ROUNDS, $G, $BaseSponge>(
                    srs,
                    filename.to_string(),
                );
            let group_map = GroupMap::<_>::setup();
            println!(
                "PROVER MEMORY PROFILE: mina fixture ({}, circuit seed {}), domain 2^{}",
                curve_name,
                seed,
                index.cs.domain.d1.size.trailing_zeros(),
            );
            println!(
                "- setup time (srs, deserialization, index): {} ms",
                setup_start.elapsed().as_millis()
            );

            let window = mem_profile::start();
            let prove_start = Instant::now();
            let proof = ProverProof::<$G, OpeningProof<$G, FULL_ROUNDS>, FULL_ROUNDS>::create_recursive::<
                $BaseSponge,
                $ScalarSponge,
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
            let prove_time = prove_start.elapsed();
            window.report("proof creation");
            println!("- time to create proof: {} ms", prove_time.as_millis());

            std::hint::black_box(proof);
        }};
    }

    if curve_name == Vesta::NAME {
        profile_curve!(Vesta, BaseSpongeVesta, ScalarSpongeVesta);
    } else if curve_name == Pallas::NAME {
        profile_curve!(Pallas, BaseSpongePallas, ScalarSpongePallas);
    } else {
        panic!("Unsupported curve: {}", curve_name);
    }
}

fn main() {
    match std::env::args().nth(1) {
        None => profile_synthetic(16),
        Some(s) => match s.parse::<u32>() {
            Ok(srs_log2) => profile_synthetic(srs_log2),
            Err(_) => profile_mina_fixture(&s),
        },
    }
}
