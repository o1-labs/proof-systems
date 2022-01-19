use kimchi::bench::BenchmarkCtx;

fn bench_proof_creation() {
    let ctx = BenchmarkCtx::default();
    ctx.create_proof();
}

fn bench_proof_verification() {
    let ctx = BenchmarkCtx::default();
    let proof = ctx.create_proof();
    ctx.batch_verification(vec![proof]);
}

iai::main!(bench_proof_creation, bench_proof_verification);
