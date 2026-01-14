//! Benchmarks for the folding/IVC operations.
//!
//! These benchmarks measure the performance of:
//! - Cross-terms computation
//! - Commitment operations
//! - Full folding iterations

use arrabbiata::{
    challenge::ChallengeTerm,
    interpreter::{self, InterpreterEnv},
    setup::IndexedRelation,
    witness::Env,
    MIN_SRS_LOG2_SIZE, VERIFIER_CIRCUIT_SIZE,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;

/// Run a single folding iteration (witness + commit + fold)
fn run_single_iteration(env: &mut Env<Fp, Fq, Vesta, Pallas>) {
    // Build the application circuit
    for _i in 0..env.indexed_relation.app_size {
        interpreter::run_app(env);
        env.reset();
    }

    // Build the verifier circuit
    for _i in 0..VERIFIER_CIRCUIT_SIZE - 1 {
        let current_instr = env.fetch_instruction();
        interpreter::run_ivc(env, current_instr);
        env.current_instruction = interpreter::fetch_next_instruction(current_instr);
        env.reset();
    }
    env.reset();

    // Commit to the program state
    env.commit_state();
    env.absorb_state();

    // Coin challenge for constraint combiner
    env.coin_challenge(ChallengeTerm::ConstraintCombiner);

    // Compute and commit cross-terms
    env.compute_cross_terms();
    env.commit_cross_terms();
    env.absorb_cross_terms();

    // Coin challenge for relation combiner
    env.coin_challenge(ChallengeTerm::RelationCombiner);

    // Fold and accumulate
    env.fold_instance();
    env.accumulate_program_state();
    env.accumulate_committed_state();

    env.reset_for_next_iteration();
    env.current_iteration += 1;
}

/// Benchmark environment creation
fn bench_env_creation(c: &mut Criterion) {
    c.bench_function("env_creation", |b| {
        b.iter(|| {
            let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
            let env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);
            black_box(env)
        })
    });
}

/// Benchmark a single folding iteration
fn bench_single_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_iteration");
    group.sample_size(10); // Expensive operation

    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

    group.bench_function("full_iteration", |b| {
        b.iter(|| {
            run_single_iteration(&mut env);
        })
    });

    group.finish();
}

/// Benchmark multiple folding iterations
fn bench_multiple_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_iterations");
    group.sample_size(10);

    for num_iters in [1, 2, 5].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_iters),
            num_iters,
            |b, &n| {
                b.iter(|| {
                    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
                    let mut env: Env<Fp, Fq, Vesta, Pallas> =
                        Env::new(BigInt::from(1u64), indexed_relation);

                    for _ in 0..n {
                        run_single_iteration(&mut env);
                    }
                    black_box(env.current_iteration)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark just the cross-terms computation
fn bench_cross_terms_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cross_terms");
    group.sample_size(10);

    // Setup: run one iteration to have accumulated state
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);
    run_single_iteration(&mut env);

    // Now benchmark just the cross-terms computation
    group.bench_function("compute_only", |b| {
        b.iter(|| {
            env.compute_cross_terms();
        })
    });

    group.bench_function("compute_and_commit", |b| {
        b.iter(|| {
            env.compute_cross_terms();
            env.commit_cross_terms();
        })
    });

    group.finish();
}

/// Benchmark commitment operations
fn bench_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitments");
    group.sample_size(10);

    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

    // Fill witness
    for _i in 0..env.indexed_relation.app_size {
        interpreter::run_app(&mut env);
        env.reset();
    }

    group.bench_function("commit_state", |b| {
        b.iter(|| {
            env.commit_state();
        })
    });

    group.finish();
}

/// Benchmark proof generation time
fn bench_proof_generation(c: &mut Criterion) {
    use arrabbiata::decider::prover::prove;

    let mut group = c.benchmark_group("proof_generation");
    group.sample_size(10);

    for num_iters in [1, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_iters),
            num_iters,
            |b, &n| {
                // Setup: run n iterations
                let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
                let mut env: Env<Fp, Fq, Vesta, Pallas> =
                    Env::new(BigInt::from(1u64), indexed_relation);

                for _ in 0..n {
                    run_single_iteration(&mut env);
                }

                b.iter(|| {
                    let proof = prove(&env).expect("proof generation should succeed");
                    black_box(proof)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark and verify proof size is constant (regression test)
fn bench_proof_size_regression(c: &mut Criterion) {
    use arrabbiata::decider::prover::prove;

    let mut group = c.benchmark_group("proof_size_regression");
    group.sample_size(10);

    // Run with different iteration counts and verify size is ~constant
    let mut sizes = Vec::new();

    for num_iters in [1, 5, 10].iter() {
        let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
        let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), indexed_relation);

        for _ in 0..*num_iters {
            run_single_iteration(&mut env);
        }

        let proof = prove(&env).expect("proof generation should succeed");
        let size = proof.estimated_size();
        sizes.push((*num_iters, size));

        group.bench_function(format!("{}_iterations_size", num_iters), |b| {
            b.iter(|| black_box(size))
        });
    }

    group.finish();

    // Verify proof sizes are approximately constant (key property of folding!)
    let base_size = sizes[0].1;
    for (iters, size) in &sizes {
        let diff = (*size as i64 - base_size as i64).abs();
        assert!(
            diff < 1000, // Allow small variance from cross-term commitment differences
            "Proof size for {} iterations ({} bytes) should be close to base size ({} bytes)",
            iters,
            size,
            base_size
        );
    }

    // Print sizes for reference
    println!("\nProof size regression results:");
    for (iters, size) in &sizes {
        println!("  {} iterations: {} bytes", iters, size);
    }
}

criterion_group!(
    benches,
    bench_env_creation,
    bench_single_iteration,
    bench_multiple_iterations,
    bench_cross_terms_computation,
    bench_commitments,
    bench_proof_generation,
    bench_proof_size_regression,
);

criterion_main!(benches);
