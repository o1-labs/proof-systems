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

fn main() {
    let mode = env::args().nth(1);
    match mode.as_deref() {
        Some("prove") => {
            let ctx = BenchmarkCtx::new(14);
            loop {
                let proof_and_public = ctx.create_proof();
                black_box(proof_and_public);
            }
        }
        Some("verify") => {
            let ctx = BenchmarkCtx::new(4);
            let proof_and_public = ctx.create_proof();
            loop {
                ctx.batch_verification(black_box(&vec![proof_and_public.clone()]));
            }
        }
        _ => panic!("you must provide an argument (prove or verify)"),
    };
}
