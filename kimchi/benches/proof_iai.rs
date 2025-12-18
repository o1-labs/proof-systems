use kimchi::bench::BenchmarkCtx;

fn bench_proof_creation() {
    let ctx = BenchmarkCtx::new(14);
    ctx.create_proof();
}

fn bench_proof_creation_and_verification() {
    let ctx = BenchmarkCtx::new(14);
    let proof_and_public = ctx.create_proof();
    ctx.batch_verification(&[proof_and_public]);
}

iai::main!(bench_proof_creation, bench_proof_creation_and_verification);
