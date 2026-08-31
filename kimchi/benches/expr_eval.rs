//! Frozen regression benchmark for gate-constraint expression evaluation.
//!
//! This benchmark is the pre/post measurement baseline for the expression
//! evaluation optimization series. It is intentionally minimal and
//! **frozen**: it exercises only public API (`Argument::combined_constraints`
//! + `Expr::evaluations` against a synthetic `Environment`), so it must
//!   keep compiling unchanged across internal refactors of `expr.rs`. Do not
//!   change what it measures; later commits may only fix compile breakage.
//!
//! Cases: `evaluations/<gate>/<domain log2>` for the five always-on gates,
//! at d1 = 2^10 (all columns fit in cache: compute-bound shape) and
//! d1 = 2^16 (columns are 16 MiB each at d8: memory-bound shape). Comparing
//! per-element cost between the two sizes is the memory-vs-compute
//! discriminator from `perf-fusion-plan.md`.
//!
//! Only `Expr::evaluations` is timed; `combined_constraints` is
//! size-independent symbolic work and is hoisted out of the timed region.
//!
//! Run with `cargo bench -p kimchi --bench expr_eval`.

use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kimchi::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        berkeley_columns::{BerkeleyChallenges, Environment, E},
        domains::EvaluationDomains,
        expr::{self, l0_1, Constants},
        gate::GateType,
        polynomials::{
            complete_add::CompleteAdd,
            endomul_scalar::EndomulScalar,
            endosclmul::EndosclMul,
            foreign_field_add::circuitgates::ForeignFieldAdd,
            foreign_field_mul::circuitgates::ForeignFieldMul,
            poseidon::Poseidon,
            range_check::circuitgates::{RangeCheck0, RangeCheck1},
            rot::Rot64,
            varbasemul::VarbaseMul,
            xor::Xor16,
        },
        wires::COLUMNS,
    },
};
use mina_curves::pasta::Fp;
use rand::Rng;
use std::{array, collections::HashMap};

/// Owned column data for a synthetic prover environment. Values are random:
/// field-operation cost is data-independent, so random data measures the
/// same work as a real witness.
struct EnvData {
    domain: EvaluationDomains<Fp>,
    witness: [Evaluations<Fp, D<Fp>>; COLUMNS],
    coefficient: [Evaluations<Fp, D<Fp>>; COLUMNS],
    vanishes: Evaluations<Fp, D<Fp>>,
    z: Evaluations<Fp, D<Fp>>,
    selectors: Vec<(GateType, Evaluations<Fp, D<Fp>>)>,
    alpha: Fp,
    beta: Fp,
    gamma: Fp,
}

fn rand_evals(rng: &mut impl Rng, d: D<Fp>) -> Evaluations<Fp, D<Fp>> {
    Evaluations::from_vec_and_domain((0..d.size()).map(|_| Fp::rand(rng)).collect(), d)
}

fn make_env_data(rng: &mut impl Rng, d1_log2: u32) -> EnvData {
    let domain = EvaluationDomains::<Fp>::create(1 << d1_log2).unwrap();
    EnvData {
        domain,
        witness: array::from_fn(|_| rand_evals(rng, domain.d8)),
        coefficient: array::from_fn(|_| rand_evals(rng, domain.d8)),
        vanishes: rand_evals(rng, domain.d8),
        z: rand_evals(rng, domain.d8),
        // Selector domains mirror the prover's column evaluations:
        // CompleteAdd at d4, the other gate selectors at d8.
        selectors: vec![
            (GateType::Poseidon, rand_evals(rng, domain.d8)),
            (GateType::VarBaseMul, rand_evals(rng, domain.d8)),
            (GateType::EndoMul, rand_evals(rng, domain.d8)),
            (GateType::EndoMulScalar, rand_evals(rng, domain.d8)),
            (GateType::CompleteAdd, rand_evals(rng, domain.d4)),
            (GateType::RangeCheck0, rand_evals(rng, domain.d8)),
            (GateType::RangeCheck1, rand_evals(rng, domain.d8)),
            (GateType::ForeignFieldAdd, rand_evals(rng, domain.d8)),
            (GateType::ForeignFieldMul, rand_evals(rng, domain.d8)),
            (GateType::Xor16, rand_evals(rng, domain.d8)),
            (GateType::Rot64, rand_evals(rng, domain.d8)),
        ],
        alpha: Fp::rand(rng),
        beta: Fp::rand(rng),
        gamma: Fp::rand(rng),
    }
}

fn make_env(data: &EnvData) -> Environment<'_, Fp> {
    let index: HashMap<_, _> = data.selectors.iter().map(|(g, e)| (*g, e)).collect();
    Environment {
        witness: &data.witness,
        coefficient: &data.coefficient,
        vanishes_on_zero_knowledge_and_previous_rows: &data.vanishes,
        z: &data.z,
        index,
        l0_1: l0_1(data.domain.d1),
        constants: Constants {
            endo_coefficient: mina_poseidon::sponge::endo_coefficient::<Fp>(),
            mds: &mina_poseidon::pasta::fp_kimchi::static_params().mds,
            zk_rows: 3,
        },
        challenges: BerkeleyChallenges {
            alpha: data.alpha,
            beta: data.beta,
            gamma: data.gamma,
            joint_combiner: Fp::from(0u64),
        },
        domain: data.domain,
        lookup: None,
    }
}

fn make_alphas(alpha: Fp) -> Alphas<Fp> {
    let mut alphas = Alphas::<Fp>::default();
    alphas.register(
        ArgumentType::Gate(GateType::Zero),
        VarbaseMul::<Fp>::CONSTRAINTS,
    );
    alphas.instantiate(alpha);
    alphas
}

/// The per-gate constraint expressions, built once outside the timed region.
fn gate_exprs(alphas: &Alphas<Fp>) -> Vec<(&'static str, E<Fp>)> {
    let mut cache = expr::Cache::default();
    vec![
        (
            "poseidon",
            Poseidon::combined_constraints(alphas, &mut cache),
        ),
        (
            "varbase_mul",
            VarbaseMul::combined_constraints(alphas, &mut cache),
        ),
        (
            "endoscl_mul",
            EndosclMul::combined_constraints(alphas, &mut cache),
        ),
        (
            "endomul_scalar",
            EndomulScalar::combined_constraints(alphas, &mut cache),
        ),
        (
            "complete_add",
            CompleteAdd::combined_constraints(alphas, &mut cache),
        ),
        (
            "range_check0",
            RangeCheck0::combined_constraints(alphas, &mut cache),
        ),
        (
            "range_check1",
            RangeCheck1::combined_constraints(alphas, &mut cache),
        ),
        (
            "foreign_field_add",
            ForeignFieldAdd::combined_constraints(alphas, &mut cache),
        ),
        (
            "foreign_field_mul",
            ForeignFieldMul::combined_constraints(alphas, &mut cache),
        ),
        ("xor16", Xor16::combined_constraints(alphas, &mut cache)),
        ("rot64", Rot64::combined_constraints(alphas, &mut cache)),
    ]
}

fn benchmark_expr_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("expr_eval");
    let mut rng = o1_utils::tests::make_test_rng(Some([0u8; 32]));

    for d1_log2 in [10u32, 16] {
        let data = make_env_data(&mut rng, d1_log2);
        let env = make_env(&data);
        let alphas = make_alphas(data.alpha);
        let exprs = gate_exprs(&alphas);

        if d1_log2 > 12 {
            group.sample_size(20);
        }
        // Per-gate cases: the five always-on gates (unchanged case names).
        for (name, e) in exprs.iter().take(5) {
            group.bench_function(format!("evaluations/{name}/{d1_log2}"), |b| {
                b.iter(|| black_box(e.evaluations(&env)))
            });
        }
        // Aggregate: every gate type kimchi's quotient loop can evaluate,
        // including the optional ones no bench circuit currently enables -
        // the quotient::gates region for a maximally-featured circuit.
        group.bench_function(format!("evaluations/all_gates/{d1_log2}"), |b| {
            b.iter(|| {
                for (_, e) in &exprs {
                    black_box(e.evaluations(&env));
                }
            })
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_expr_eval);
criterion_main!(benches);
