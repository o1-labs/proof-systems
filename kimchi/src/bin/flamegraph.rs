use core::{mem, ptr};
use std::env;

use kimchi::bench::BenchmarkCtx;

/// function to avoid optimizations by the compiler
/// taken from <https://docs.rs/criterion/latest/src/criterion/lib.rs.html#171>
pub fn black_box<T>(dummy: T) -> T {
    unsafe {
        let ret = ptr::read_volatile(&dummy);
        mem::forget(dummy);
        ret
    }
}

/// Optional second CLI argument: how many iterations to run before returning.
/// Defaults to unbounded, which is what `cargo flamegraph` expects. Pass a
/// finite count when profiling with `--features hotpath`, so that `main`
/// returns and the hotpath report is printed on exit.
fn iterations() -> Option<u64> {
    env::args()
        .nth(2)
        .map(|n| n.parse().expect("iteration count must be an integer"))
}

/// Returns `true` while the (optionally bounded) loop should keep going.
fn keep_going(done: u64, budget: Option<u64>) -> bool {
    budget.is_none_or(|n| done < n)
}

#[hotpath::main(limit = 40)]
fn main() {
    let mode = env::args().nth(1);
    let budget = iterations();

    match mode.as_deref() {
        Some("prove") => {
            let ctx = BenchmarkCtx::new(14);
            let mut done = 0;
            while keep_going(done, budget) {
                let proof_and_public = ctx.create_proof();
                black_box(proof_and_public);
                done += 1;
            }
        }
        Some("verify") => {
            let ctx = BenchmarkCtx::new(4);
            let proof_and_public = ctx.create_proof();
            let mut done = 0;
            while keep_going(done, budget) {
                ctx.batch_verification(black_box(std::slice::from_ref(&proof_and_public)));
                done += 1;
            }
        }
        _ => panic!("you must provide an argument (prove or verify)"),
    };
}
