use kimchi::bench::BenchmarkCtx;

fn main() {
    let ctx = BenchmarkCtx::default();
    let proof = ctx.create_proof();
    for _ in 0..10 {
        ctx.batch_verification(vec![proof.clone()]);
    }
}
