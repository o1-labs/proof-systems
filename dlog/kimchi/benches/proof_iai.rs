use kimchi::bench::BenchmarkCtx;

fn bench_proof_creation() {
    let ctx = BenchmarkCtx::new();
    ctx.create_proof();
}

iai::main!(bench_proof_creation);
