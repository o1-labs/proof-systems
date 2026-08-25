//! Option C: surgical A/B of `ProverIndex::perm_quot`, the only proving-path
//! function touched by PR #3586.
//!
//! This file is byte-identical on both branches; run it on each and compare
//! with criterion baselines:
//!
//!   cargo bench --bench perm_quot -- --save-baseline base   # on merge-base
//!   cargo bench --bench perm_quot -- --baseline base        # on pr-3586
//!
//! It also measures a full `create_proof` at the same domain size, so the
//! share-of-total ratio (and therefore the ceiling on any end-to-end gain)
//! falls straight out of the two numbers.

use ark_ff::{UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::{
    bench::BenchmarkCtx,
    circuits::{
        gate::CircuitGate,
        polynomial::WitnessOverDomains,
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    prover_index::{testing::new_index_for_test, ProverIndex},
};
use mina_curves::pasta::{Fp, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::ipa::SRS;
use std::array;

type Index = ProverIndex<FULL_ROUNDS, Vesta, SRS<Vesta>>;

/// Everything `perm_quot` needs, built exactly the way `ProverProof::create`
/// builds it (padding + zk-row randomisation + real permutation accumulator),
/// so the benchmarked call sees production-shaped data.
struct PermInputs {
    index: Index,
    lagrange: WitnessOverDomains<Fp>,
    z_poly: DensePolynomial<Fp>,
    beta: Fp,
    gamma: Fp,
    alphas: [Fp; 3],
}

fn setup(log_n: u32) -> PermInputs {
    let rng = &mut rand::rngs::OsRng;

    let num_gates = ((1 << log_n) - 10) as usize;
    let gates = (0..num_gates)
        .map(|row| {
            CircuitGate::create_generic_gadget(
                Wire::for_row(row),
                GenericGateSpec::Const(1u32.into()),
                None,
            )
        })
        .collect();

    let index: Index = new_index_for_test(gates, 0);
    assert_eq!(index.cs.domain.d1.log_size_of_group, log_n);

    // Force the lazy caches so their cost is not attributed to `perm_quot`.
    let _ = index.cs.precomputations();
    let _ = index.column_evaluations.get();

    // Same witness preparation as the prover: pad to the domain, then
    // randomise the trailing zk rows.
    let domain_size = index.cs.domain.d1.size();
    let zk_rows = index.cs.zk_rows as usize;
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::from(1u32); num_gates]);
    for w in &mut witness {
        w.extend(std::iter::repeat_n(Fp::zero(), domain_size - num_gates));
        for row in w.iter_mut().rev().take(zk_rows) {
            *row = Fp::rand(rng);
        }
    }

    let witness_poly: [DensePolynomial<Fp>; COLUMNS] = array::from_fn(|i| {
        Evaluations::<Fp, D<Fp>>::from_vec_and_domain(witness[i].clone(), index.cs.domain.d1)
            .interpolate()
    });

    let beta = Fp::rand(rng);
    let gamma = Fp::rand(rng);
    let z_poly = index
        .perm_aggreg(&witness, &beta, &gamma, rng)
        .expect("permutation aggregation failed");
    let lagrange = index.cs.evaluate(&witness_poly, &z_poly);

    // `perm_quot` consumes exactly three powers of alpha; their values do not
    // affect the cost.
    let alphas = [Fp::rand(rng), Fp::rand(rng), Fp::rand(rng)];

    PermInputs {
        index,
        lagrange,
        z_poly,
        beta,
        gamma,
        alphas,
    }
}

fn bench_perm_quot(c: &mut Criterion) {
    let mut group = c.benchmark_group("perm_quot");
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(20));

    for log_n in [10u32, 14, 16] {
        let inputs = setup(log_n);
        // Sanity: the call must actually succeed, not error out into a fast path.
        inputs
            .index
            .perm_quot(
                &inputs.lagrange,
                inputs.beta,
                inputs.gamma,
                &inputs.z_poly,
                inputs.alphas.into_iter(),
            )
            .expect("perm_quot failed");

        group.bench_function(format!("perm_quot (2^{log_n} rows)"), |b| {
            b.iter(|| {
                black_box(
                    inputs
                        .index
                        .perm_quot(
                            black_box(&inputs.lagrange),
                            inputs.beta,
                            inputs.gamma,
                            black_box(&inputs.z_poly),
                            inputs.alphas.into_iter(),
                        )
                        .unwrap(),
                )
            })
        });
    }

    group.finish()
}

/// Full proof at the same sizes, to turn the `perm_quot` delta into a share of
/// the number that actually ships.
fn bench_proof_for_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_for_ratio");
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(30));
    group.sample_size(10);

    for log_n in [10u32, 14, 16] {
        let ctx = BenchmarkCtx::new(log_n);
        group.bench_function(format!("create_proof (2^{log_n} rows)"), |b| {
            b.iter(|| black_box(ctx.create_proof()))
        });
    }

    group.finish()
}

criterion_group!(benches, bench_perm_quot, bench_proof_for_ratio);
criterion_main!(benches);
