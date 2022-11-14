use std::env;

use kimchi::bench::BenchmarkCtx;

/// function to avoid optimizations by the compiler
/// taken from <https://docs.rs/criterion/latest/src/criterion/lib.rs.html#171>
pub fn black_box<T>(dummy: T) -> T {
    unsafe {
        let ret = std::ptr::read_volatile(&dummy);
        std::mem::forget(dummy);
        ret
    }
}

fn main() {
    let mode = env::args().nth(1);
    match mode.as_deref() {
        Some("prove") => {
            let ctx = BenchmarkCtx::new(1 << 14);
            loop {
                let proof = ctx.create_proof();
                black_box(proof);
            }
        }
        Some("verify") => {
            let ctx = BenchmarkCtx::new(1 << 4);
            let proof = ctx.create_proof();
            loop {
                ctx.batch_verification(black_box(vec![proof.clone()]));
            }
        }
        _ => panic!("you must provide an argument (prove or verify)"),
    };
}
