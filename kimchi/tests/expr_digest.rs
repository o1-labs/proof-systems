//! Frozen output digest for gate-constraint expression evaluation.
//!
//! Evaluates each always-on gate's combined constraints against a fully
//! deterministic synthetic environment and asserts a hard-coded digest of the
//! resulting evaluation vectors. Every optimization to the expression
//! evaluator must preserve the evaluations bit-for-bit, so this digest must
//! NEVER change. If it does, the change under test altered the prover's
//! polynomials and must be rejected.
//!
//! The digest was recorded at the base of the optimization series
//! (branch `perf/expr-eval`).

use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest};
use kimchi::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        berkeley_columns::{BerkeleyChallenges, Environment},
        domains::EvaluationDomains,
        expr::{self, l0_1, Constants},
        gate::GateType,
        polynomials::{
            complete_add::CompleteAdd, endomul_scalar::EndomulScalar, endosclmul::EndosclMul,
            poseidon::Poseidon, varbasemul::VarbaseMul,
        },
        wires::COLUMNS,
    },
};
use mina_curves::pasta::Fp;
use rand::Rng;
use std::{array, collections::HashMap};

fn rand_evals(rng: &mut impl Rng, d: D<Fp>) -> Evaluations<Fp, D<Fp>> {
    Evaluations::from_vec_and_domain((0..d.size()).map(|_| Fp::rand(rng)).collect(), d)
}

#[test]
fn test_gate_evaluations_digest_regression() {
    let mut rng = o1_utils::tests::make_test_rng(Some([0u8; 32]));

    let domain = EvaluationDomains::<Fp>::create(1 << 6).unwrap();
    let witness: [Evaluations<Fp, D<Fp>>; COLUMNS] =
        array::from_fn(|_| rand_evals(&mut rng, domain.d8));
    let coefficient: [Evaluations<Fp, D<Fp>>; COLUMNS] =
        array::from_fn(|_| rand_evals(&mut rng, domain.d8));
    let vanishes = rand_evals(&mut rng, domain.d8);
    let z = rand_evals(&mut rng, domain.d8);
    // Selector domains mirror the prover's column evaluations: CompleteAdd
    // at d4, the other gate selectors at d8.
    let selectors = [
        (GateType::Poseidon, rand_evals(&mut rng, domain.d8)),
        (GateType::VarBaseMul, rand_evals(&mut rng, domain.d8)),
        (GateType::EndoMul, rand_evals(&mut rng, domain.d8)),
        (GateType::EndoMulScalar, rand_evals(&mut rng, domain.d8)),
        (GateType::CompleteAdd, rand_evals(&mut rng, domain.d4)),
    ];
    let alpha = Fp::rand(&mut rng);

    let env = Environment {
        witness: &witness,
        coefficient: &coefficient,
        vanishes_on_zero_knowledge_and_previous_rows: &vanishes,
        z: &z,
        index: selectors
            .iter()
            .map(|(g, e)| (*g, e))
            .collect::<HashMap<_, _>>(),
        l0_1: l0_1(domain.d1),
        constants: Constants {
            endo_coefficient: mina_poseidon::sponge::endo_coefficient::<Fp>(),
            mds: &mina_poseidon::pasta::fp_kimchi::static_params().mds,
            zk_rows: 3,
        },
        challenges: BerkeleyChallenges {
            alpha,
            beta: Fp::rand(&mut rng),
            gamma: Fp::rand(&mut rng),
            joint_combiner: Fp::from(0u64),
        },
        domain,
        lookup: None,
    };

    let mut alphas = Alphas::<Fp>::default();
    alphas.register(
        ArgumentType::Gate(GateType::Zero),
        VarbaseMul::<Fp>::CONSTRAINTS,
    );
    alphas.instantiate(alpha);

    let mut cache = expr::Cache::default();
    let mut hasher = Blake2b512::new();
    for e in [
        Poseidon::combined_constraints(&alphas, &mut cache),
        VarbaseMul::combined_constraints(&alphas, &mut cache),
        EndosclMul::combined_constraints(&alphas, &mut cache),
        EndomulScalar::combined_constraints(&alphas, &mut cache),
        CompleteAdd::combined_constraints(&alphas, &mut cache),
    ] {
        let evals = e.evaluations(&env);
        let mut bytes = Vec::new();
        evals
            .evals
            .serialize_compressed(&mut bytes)
            .expect("serialize evaluations");
        hasher.update(&bytes);
    }

    let digest = hex::encode(hasher.finalize());
    assert_eq!(
        digest,
        "ab9826dd00d2764ab40707049bd39f3d579deedac512a29edd65b68f002a55acb9f0dac1b22b9360354f9ec94f63e9610b54d0e79682ae0f7cbf6645ba965791",
        "gate constraint evaluations changed: the expression-evaluator \
         optimization under test is not behavior-preserving"
    );
}
