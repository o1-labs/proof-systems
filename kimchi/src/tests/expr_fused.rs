//! Equivalence tests for the fused chunked expression evaluator:
//! `Expr::evaluations_fused` must produce bit-identical results to the
//! legacy `Expr::evaluations` on every gate-constraint expression and on
//! targeted expressions covering the node types the gates do not exercise.

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        berkeley_columns::{BerkeleyChallenges, Column, Environment, E},
        domains::EvaluationDomains,
        expr::{self, l0_1, Constants, Expr, ExprInner, Operations, RowOffset, Variable},
        gate::{CurrOrNext, GateType},
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
use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use mina_curves::pasta::Fp;
use rand::Rng;
use std::{array, collections::HashMap};

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

/// Every gate-constraint expression evaluates identically under the legacy
/// and fused evaluators, at a sub-chunk domain (partial final chunk) and a
/// multi-chunk domain.
#[test]
fn fused_matches_legacy_on_gate_constraints() {
    let mut rng = o1_utils::tests::make_test_rng(Some([1u8; 32]));
    for d1_log2 in [6u32, 10] {
        let data = make_env_data(&mut rng, d1_log2);
        let env = make_env(&data);
        let mut alphas = Alphas::<Fp>::default();
        alphas.register(
            ArgumentType::Gate(GateType::Zero),
            VarbaseMul::<Fp>::CONSTRAINTS,
        );
        alphas.instantiate(data.alpha);

        for (name, e) in gate_exprs(&alphas) {
            let legacy = e.evaluations(&env);
            let fused = e.evaluations_fused(&env);
            assert_eq!(
                legacy.domain(),
                fused.domain(),
                "{name} domain (2^{d1_log2})"
            );
            assert_eq!(legacy.evals, fused.evals, "{name} evals (2^{d1_log2})");
        }
    }
}

/// Targeted expressions for node types the gate constraints do not reach:
/// `UnnormalizedLagrangeBasis` (all offset shapes),
/// `VanishesOnZeroKnowledgeAndPreviousRows`, `Pow` edge exponents, `Double`,
/// and constant-only results.
#[test]
fn fused_matches_legacy_on_targeted_expressions() {
    type FE = Expr<Fp, Column>;

    fn cell(i: usize, row: CurrOrNext) -> FE {
        Operations::Atom(ExprInner::Cell(Variable {
            col: Column::Witness(i),
            row,
        }))
    }
    fn lagrange(zk_rows: bool, offset: i32) -> FE {
        Operations::Atom(ExprInner::UnnormalizedLagrangeBasis(RowOffset {
            zk_rows,
            offset,
        }))
    }
    fn constant(x: u64) -> FE {
        Operations::Atom(ExprInner::Constant(Fp::from(x)))
    }
    fn add(a: FE, b: FE) -> FE {
        Operations::Add(Box::new(a), Box::new(b))
    }
    fn sub(a: FE, b: FE) -> FE {
        Operations::Sub(Box::new(a), Box::new(b))
    }
    fn mul(a: FE, b: FE) -> FE {
        Operations::Mul(Box::new(a), Box::new(b))
    }
    fn pow(a: FE, p: u64) -> FE {
        Operations::Pow(Box::new(a), p)
    }
    fn double(a: FE) -> FE {
        Operations::Double(Box::new(a))
    }
    fn square(a: FE) -> FE {
        Operations::Square(Box::new(a))
    }
    let vanishes: FE = Operations::Atom(ExprInner::VanishesOnZeroKnowledgeAndPreviousRows);

    let cases: Vec<(&'static str, FE)> = vec![
        (
            "cell_product",
            mul(cell(0, CurrOrNext::Curr), cell(1, CurrOrNext::Next)),
        ),
        (
            "lagrange_offsets",
            add(
                add(lagrange(false, 0), lagrange(false, 3)),
                add(lagrange(false, -1), lagrange(true, 0)),
            ),
        ),
        (
            "lagrange_times_cell",
            mul(lagrange(true, -1), cell(2, CurrOrNext::Curr)),
        ),
        (
            "vanishes_times_cell",
            mul(vanishes, cell(3, CurrOrNext::Curr)),
        ),
        ("pow_zero", pow(cell(4, CurrOrNext::Curr), 0)),
        ("pow_one", pow(cell(4, CurrOrNext::Curr), 1)),
        ("pow_five", pow(cell(4, CurrOrNext::Curr), 5)),
        (
            "double_square",
            double(square(sub(cell(5, CurrOrNext::Curr), constant(7)))),
        ),
        (
            "constant_only",
            add(constant(3), mul(constant(4), constant(5))),
        ),
        (
            "scalar_buffer_mix",
            sub(constant(11), mul(constant(2), cell(6, CurrOrNext::Next))),
        ),
    ];

    let mut rng = o1_utils::tests::make_test_rng(Some([2u8; 32]));
    for d1_log2 in [6u32, 10] {
        let data = make_env_data(&mut rng, d1_log2);
        let env = make_env(&data);
        for (name, e) in &cases {
            let legacy = e.evaluations(&env);
            let fused = e.evaluations_fused(&env);
            assert_eq!(
                legacy.domain(),
                fused.domain(),
                "{name} domain (2^{d1_log2})"
            );
            assert_eq!(legacy.evals, fused.evals, "{name} evals (2^{d1_log2})");
        }
    }
}
