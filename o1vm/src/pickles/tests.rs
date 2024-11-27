use std::{collections::BTreeMap, time::Instant};

use super::{
    super::interpreters::mips::column::SCRATCH_SIZE,
    proof::{ProofInputs, WitnessColumns},
    prover::prove,
};
use crate::{
    interpreters::mips::{
        column::SCRATCH_SIZE_INVERSE,
        constraints as mips_constraints,
        interpreter::{self, InterpreterEnv},
        Instruction,
    },
    lookups::LookupTableIDs,
    pickles::{verifier::verify, MAXIMUM_DEGREE_CONSTRAINTS, TOTAL_NUMBER_OF_CONSTRAINTS},
};
use ark_ff::{Field, One, UniformRand, Zero};
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
use strum::IntoEnumIterator;

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

fn zero_to_n_minus_one(n: usize) -> Vec<Fq> {
    (0..n).map(|i| Fq::from((i) as u64)).collect()
}

#[test]
fn test_small_circuit() {
    let domain = EvaluationDomains::<Fq>::create(8).unwrap();
    let srs = SRS::create(8);
    let proof_input = ProofInputs::<Pallas, LookupTableIDs> {
        evaluations: WitnessColumns {
            scratch: std::array::from_fn(|_| zero_to_n_minus_one(8)),
            scratch_inverse: std::array::from_fn(|_| (0..8).map(|_| Fq::zero()).collect()),
            instruction_counter: zero_to_n_minus_one(8)
                .into_iter()
                .map(|x| x + Fq::one())
                .collect(),
            error: (0..8)
                .map(|i| -Fq::from((i * SCRATCH_SIZE + (i + 1)) as u64))
                .collect(),
            selector: zero_to_n_minus_one(8),
        },
        logups: BTreeMap::new(),
    };
    let mut expr = Expr::zero();
    for i in 0..SCRATCH_SIZE + SCRATCH_SIZE_INVERSE + 2 {
        expr += Expr::cell(Column::Relation(i), CurrOrNext::Curr);
    }
    let mut rng = make_test_rng(None);

    type BaseSponge = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi>;

    let proof = prove::<Pallas, BaseSponge, ScalarSponge, _, LookupTableIDs>(
        domain,
        &srs,
        proof_input,
        &[expr.clone()],
        &mut rng,
    )
    .unwrap();

    let instant_before_verification = Instant::now();
    let verif = verify::<Pallas, BaseSponge, ScalarSponge, LookupTableIDs>(
        domain,
        &srs,
        &[expr.clone()],
        &proof,
    );
    let instant_after_verification = Instant::now();
    debug!(
        "Verification took: {} ms",
        (instant_after_verification - instant_before_verification).as_millis()
    );
    assert!(verif, "Verification fails");
}

#[test]
fn test_arkworks_batch_inversion_with_only_zeroes() {
    let input = vec![Fq::zero(); 8];
    let exp_output = vec![Fq::zero(); 8];
    let mut output = input.clone();
    ark_ff::batch_inversion::<Fq>(&mut output);
    assert_eq!(output, exp_output);
}

#[test]
fn test_arkworks_batch_inversion_with_zeroes_and_ones() {
    let input: Vec<Fq> = vec![Fq::zero(), Fq::one(), Fq::zero()];
    let exp_output: Vec<Fq> = vec![Fq::zero(), Fq::one(), Fq::zero()];
    let mut output: Vec<Fq> = input.clone();
    ark_ff::batch_inversion::<Fq>(&mut output);
    assert_eq!(output, exp_output);
}

#[test]
fn test_arkworks_batch_inversion_with_zeroes_and_random() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let input: Vec<Fq> = vec![Fq::zero(), Fq::rand(&mut rng), Fq::one()];
    let exp_output: Vec<Fq> = vec![Fq::zero(), input[1].inverse().unwrap(), Fq::one()];
    let mut output: Vec<Fq> = input.clone();
    ark_ff::batch_inversion::<Fq>(&mut output);
    assert_eq!(output, exp_output);
}
