#![feature(test)]

extern crate test;

use std::env;

use test::black_box;

use kimchi::bench::BenchmarkCtx;

fn main() {
    let mode = env::args().skip(1).next();
    match mode.as_deref() {
        Some("prove") => {
            let ctx = BenchmarkCtx::default();
            loop {
                let proof = ctx.create_proof();
                black_box(proof);
            }
        }
        Some("verify") => {
            let ctx = BenchmarkCtx::default();
            let proof = ctx.create_proof();
            loop {
                ctx.batch_verification(black_box(vec![proof.clone()]));
            }
        }
        _ => panic!("you must provide an argument (prove or verify)"),
    };
}
