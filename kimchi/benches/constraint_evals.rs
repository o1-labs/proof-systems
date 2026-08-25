//! Surgical A/B of the constraint-polynomial evaluation that PR #3588 changes.
//!
//! The PR claims "a 1/8 = 12.5% speed-up for this part of the prover". This
//! file rebuilds the prover's `Environment` exactly as `ProverProof::create`
//! does and times `Expr::evaluations(&env)` for the generic constraint (d4,
//! stride 4 -> 25% of rows skipped) and for the always-on gate constraints
//! (d8, stride 8 -> 12.5% of rows skipped).
//!
//! Byte-identical on both branches:
//!   cargo bench --bench constraint_evals

use ark_ff::{UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use kimchi::{
    alphas::Alphas,
    bench::BenchmarkCtx,
    circuits::{
        argument::{Argument, DynArgument},
        berkeley_columns::{BerkeleyChallenges, Environment},
        expr::{l0_1, Cache, Constants},
        gate::{CircuitGate, GateType},
        polynomials::{
            complete_add::CompleteAdd,
            endomul_scalar::EndomulScalar,
            endosclmul::EndosclMul,
            generic::{Generic, GenericGateSpec},
            poseidon::Poseidon,
            varbasemul::VarbaseMul,
        },
        wires::{Wire, COLUMNS},
    },
    curve::KimchiCurve,
    prover_index::{testing::new_index_for_test, ProverIndex},
};
use mina_curves::pasta::{Fp, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::ipa::SRS;
use std::{array, collections::HashMap};

type Index = ProverIndex<FULL_ROUNDS, Vesta, SRS<Vesta>>;

struct Ctx {
    index: Index,
    w8: [Evaluations<Fp, D<Fp>>; COLUMNS],
    z8: Evaluations<Fp, D<Fp>>,
    precomp:
        std::sync::Arc<kimchi::circuits::domain_constant_evaluation::DomainConstantEvaluations<Fp>>,
    all_alphas: Alphas<Fp>,
    alpha: Fp,
    beta: Fp,
    gamma: Fp,
}

fn setup(log_n: u32) -> Ctx {
    let rng = &mut rand::rngs::OsRng;

    let num_gates = ((1 << log_n) - 10) as usize;
    let gates: Vec<CircuitGate<Fp>> = (0..num_gates)
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
    let precomp = index.cs.precomputations();
    let _ = index.column_evaluations.get();

    // Prover-identical witness preparation.
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
    let alpha = Fp::rand(rng);
    let z_poly = index.perm_aggreg(&witness, &beta, &gamma, rng).unwrap();

    // Evaluate over d8 directly rather than via `ConstraintSystem::evaluate`, so
    // this bench compiles both before and after #3598 reshaped
    // `WitnessOverDomains`. Same values either way.
    let d8 = index.cs.domain.d8;
    let w8: [Evaluations<Fp, D<Fp>>; COLUMNS] =
        array::from_fn(|i| witness_poly[i].evaluate_over_domain_by_ref(d8));
    let z8 = z_poly.evaluate_over_domain_by_ref(d8);

    let mut all_alphas = index.powers_of_alpha.clone();
    all_alphas.instantiate(alpha);

    Ctx {
        index,
        precomp,
        w8,
        z8,
        all_alphas,
        alpha,
        beta,
        gamma,
    }
}

fn make_env(ctx: &Ctx) -> Environment<'_, Fp> {
    let ce = ctx.index.column_evaluations.get();
    let mds = &<Vesta as KimchiCurve<FULL_ROUNDS>>::sponge_params().mds;
    let mut index_evals = HashMap::new();
    index_evals.insert(GateType::Generic, &ce.generic_selector4);
    index_evals.insert(GateType::Poseidon, &ce.poseidon_selector8);
    index_evals.insert(GateType::CompleteAdd, &ce.complete_add_selector4);
    index_evals.insert(GateType::VarBaseMul, &ce.mul_selector8);
    index_evals.insert(GateType::EndoMul, &ce.emul_selector8);
    index_evals.insert(GateType::EndoMulScalar, &ce.endomul_scalar_selector8);

    Environment {
        constants: Constants {
            endo_coefficient: ctx.index.cs.endo,
            mds,
            zk_rows: ctx.index.cs.zk_rows,
        },
        challenges: BerkeleyChallenges {
            alpha: ctx.alpha,
            beta: ctx.beta,
            gamma: ctx.gamma,
            joint_combiner: Fp::zero(),
        },
        witness: &ctx.w8,
        coefficient: &ce.coefficients8,
        vanishes_on_zero_knowledge_and_previous_rows: &ctx
            .precomp
            .vanishes_on_zero_knowledge_and_previous_rows,
        z: &ctx.z8,
        l0_1: l0_1(ctx.index.cs.domain.d1),
        domain: ctx.index.cs.domain,
        index: index_evals,
        lookup: None,
    }
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("constraint_evals");
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(20));

    for log_n in [10u32, 14, 16] {
        let ctx = setup(log_n);
        let env = make_env(&ctx);

        // Build the constraint expressions ONCE, outside the timed region:
        // `combined_constraints` is symbolic work whose cost is independent of
        // the domain size, and it would otherwise swamp the measurement.
        let mut cache = Cache::default();
        let generic_constraint =
            <Generic<Fp> as Argument<Fp>>::combined_constraints(&ctx.all_alphas, &mut cache);
        let gate_list: [&dyn DynArgument<Fp>; 5] = [
            &CompleteAdd::default(),
            &VarbaseMul::default(),
            &EndosclMul::default(),
            &EndomulScalar::default(),
            &Poseidon::default(),
        ];
        let gate_constraints: Vec<_> = gate_list
            .iter()
            .map(|g| g.combined_constraints(&ctx.all_alphas, &mut cache))
            .collect();

        // d4 path: stride 4, so the PR skips 25% of rows here.
        group.bench_function(format!("generic (d4) (2^{log_n} rows)"), |b| {
            b.iter(|| black_box(generic_constraint.evaluations(black_box(&env))))
        });

        // d8 path: stride 8, the 1/8 = 12.5% the PR claims.
        group.bench_function(format!("gates (d8) (2^{log_n} rows)"), |b| {
            b.iter(|| {
                for constraint in &gate_constraints {
                    black_box(constraint.evaluations(black_box(&env)));
                }
            })
        });
    }

    group.finish();

    let mut prf = c.benchmark_group("proof_for_ratio");
    prf.sampling_mode(SamplingMode::Flat);
    prf.measurement_time(std::time::Duration::from_secs(30));
    prf.sample_size(10);
    let log_n = 16u32;
    let ctx = BenchmarkCtx::new(log_n);
    prf.bench_function(format!("create_proof (2^{log_n} rows)"), |b| {
        b.iter(|| black_box(ctx.create_proof()))
    });
    prf.finish()
}

criterion_group!(benches, bench);
criterion_main!(benches);
