//! Option E: deterministic allocation / retained-memory accounting for PR #3586.
//!
//! Byte-identical on both branches. Counts are exact integers produced by a
//! wrapping global allocator, so unlike wall-clock they need no statistics and
//! no quiet machine:
//!
//!   cargo run --release --example alloc_report
//!
//! Reports, per domain size:
//!   * dce_alloc_bytes      - bytes allocated building DomainConstantEvaluations (claim C1)
//!   * dce_retained_bytes   - bytes the resulting struct holds (claim C3)
//!   * index_alloc_bytes    - bytes allocated building a full prover index
//!   * index_retained_bytes - bytes the prover index holds
//!   * proof_alloc_bytes    - bytes allocated producing one proof (claim C2)
//!   * proof_peak_bytes     - peak live-heap increase during one proof

use kimchi::{
    bench::BenchmarkCtx,
    circuits::{domain_constant_evaluation::DomainConstantEvaluations, domains::EvaluationDomains},
};
use mina_curves::pasta::Fp;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

static TOTAL: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

fn on_alloc(size: usize) {
    TOTAL.fetch_add(size, Relaxed);
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            on_alloc(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            on_alloc(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size > layout.size() {
                on_alloc(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn total() -> usize {
    TOTAL.load(Relaxed)
}
fn live() -> usize {
    LIVE.load(Relaxed)
}
fn reset_peak() {
    PEAK.store(live(), Relaxed);
}
fn peak() -> usize {
    PEAK.load(Relaxed)
}

fn main() {
    // Warm rayon's pool and the lazily-initialised field/curve tables so their
    // one-off allocations are not attributed to a measured phase.
    {
        let warm = BenchmarkCtx::new(10);
        let _ = warm.create_proof();
    }

    const ZK_ROWS: u64 = 3;

    for log_n in [10u32, 14, 16] {
        let n = 1usize << log_n;

        // --- claim C1 / C3: DomainConstantEvaluations ---
        let domain = EvaluationDomains::<Fp>::create(n).unwrap();
        let (t0, l0) = (total(), live());
        let dce = DomainConstantEvaluations::<Fp>::create(domain, ZK_ROWS).unwrap();
        let dce_alloc = total() - t0;
        let dce_retained = live() - l0;
        drop(dce);

        // --- prover index ---
        let (t1, l1) = (total(), live());
        let ctx = BenchmarkCtx::new(log_n);
        let index_alloc = total() - t1;
        let index_retained = live() - l1;

        // --- claim C2: one proof ---
        reset_peak();
        let t2 = total();
        let l2 = live();
        let proof = ctx.create_proof();
        let proof_alloc = total() - t2;
        let proof_peak = peak() - l2;
        drop(proof);
        drop(ctx);

        println!("size = 2^{log_n}");
        println!("  dce_alloc_bytes      = {dce_alloc}");
        println!("  dce_retained_bytes   = {dce_retained}");
        println!("  index_alloc_bytes    = {index_alloc}");
        println!("  index_retained_bytes = {index_retained}");
        println!("  proof_alloc_bytes    = {proof_alloc}");
        println!("  proof_peak_bytes     = {proof_peak}");
    }
}
