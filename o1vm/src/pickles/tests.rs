use std::time::Instant;

use super::{
    super::interpreters::mips::witness::SCRATCH_SIZE,
    proof::{ProofInputs, WitnessColumns},
    prover::prove,
};
use crate::{
    interpreters::mips::{
        constraints as mips_constraints, interpreter, interpreter::InterpreterEnv, Instruction,
    },
    pickles::{verifier::verify, MAXIMUM_DEGREE_CONSTRAINTS, TOTAL_NUMBER_OF_CONSTRAINTS},
};
use ark_ff::{One, Zero};
use interpreter::{ITypeInstruction, JTypeInstruction, RTypeInstruction};
use kimchi::circuits::{domains::EvaluationDomains, expr::Expr, gate::CurrOrNext};
use kimchi_msm::{columns::Column, expr::E};
use log::debug;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::tests::make_test_rng;
use poly_commitment::SRS;
use strum::{EnumCount, IntoEnumIterator};

#[test]
fn test_regression_constraints_with_selectors() {
    let constraints = {
        let mut mips_con_env = mips_constraints::Env::<Fp>::default();
        let mut constraints = Instruction::iter()
            .flat_map(|instr_typ| instr_typ.into_iter())
            .fold(vec![], |mut acc, instr| {
                interpreter::interpret_instruction(&mut mips_con_env, instr);
                let selector = mips_con_env.get_selector();
                let constraints_with_selector: Vec<E<Fp>> = mips_con_env
                    .get_constraints()
                    .into_iter()
                    .map(|c| selector.clone() * c)
                    .collect();
                acc.extend(constraints_with_selector);
                mips_con_env.reset();
                acc
            });
        constraints.extend(mips_con_env.get_selector_constraints());
        constraints
    };

    assert_eq!(constraints.len(), TOTAL_NUMBER_OF_CONSTRAINTS);

    let max_degree = constraints.iter().map(|c| c.degree(1, 0)).max().unwrap();
    assert_eq!(max_degree, MAXIMUM_DEGREE_CONSTRAINTS);
}

#[test]
// Sanity check that we have as many selector as we have instructions
fn test_regression_selectors_for_instructions() {
    let mips_con_env = mips_constraints::Env::<Fp>::default();
    let constraints = mips_con_env.get_selector_constraints();
    assert_eq!(
        // We substract 1 as we have one boolean check per sel
        // and 1 constraint to check that one and only one
        // sel is activated
        constraints.len() - 1,
        // We could use N_MIPS_SEL_COLS, but sanity check in case this value is
        // changed.
        RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT
    );
    // All instructions are degree 1 or 2.
    constraints
        .iter()
        .for_each(|c| assert!(c.degree(1, 0) == 2 || c.degree(1, 0) == 1));
}

fn zero_to_n_minus_one(n: usize) -> Vec<Fq> {
    (0..n).map(|i| Fq::from((i) as u64)).collect()
}

#[test]
fn test_small_circuit() {
    let domain = EvaluationDomains::<Fq>::create(8).unwrap();
    let srs = SRS::create(8);
    let proof_input = ProofInputs::<Fq> {
        evaluations: WitnessColumns {
            scratch: std::array::from_fn(|_| zero_to_n_minus_one(8)),
            instruction_counter: zero_to_n_minus_one(8)
                .into_iter()
                .map(|x| x + Fq::one())
                .collect(),
            error: (0..8)
                .map(|i| -Fq::from((i * SCRATCH_SIZE + (i + 1)) as u64))
                .collect(),
            selector: zero_to_n_minus_one(8),
        },
    };
    let mut expr = Expr::zero();
    for i in 0..SCRATCH_SIZE + 2 {
        expr += Expr::cell(Column::Relation(i), CurrOrNext::Curr);
    }
    let mut rng = make_test_rng(None);

    type BaseSponge = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi>;

    let proof = prove::<Pallas, BaseSponge, ScalarSponge, _>(
        domain,
        &srs,
        proof_input,
        &[expr.clone()],
        &mut rng,
    )
    .unwrap();

    let instant_before_verification = Instant::now();
    let verif = verify::<Pallas, BaseSponge, ScalarSponge>(domain, &srs, &[expr.clone()], &proof);
    let instant_after_verification = Instant::now();
    debug!(
        "Verification took: {} ms",
        (instant_after_verification - instant_before_verification).as_millis()
    );
    assert!(verif, "Verification fails");
}
