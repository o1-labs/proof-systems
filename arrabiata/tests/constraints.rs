use num_bigint::BigInt;
use std::collections::HashMap;

use arrabiata::{
    constraints,
    interpreter::{self, Instruction, InterpreterEnv},
    poseidon_3_60_0_5_5_fp, poseidon_3_60_0_5_5_fq,
};
use mina_curves::pasta::fields::{Fp, Fq};

fn helper_compute_constraints_gadget(instr: Instruction, exp_constraints: usize) {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigInt::from(0_usize))
    };

    interpreter::run_ivc(&mut constraints_fp, instr);
    assert_eq!(constraints_fp.constraints.len(), exp_constraints);

    let mut constraints_fq = {
        let poseidon_mds = poseidon_3_60_0_5_5_fq::static_params().mds.clone();
        constraints::Env::<Fq>::new(poseidon_mds.to_vec(), BigInt::from(0_usize))
    };
    interpreter::run_ivc(&mut constraints_fq, instr);
    assert_eq!(constraints_fq.constraints.len(), exp_constraints);
}

fn helper_check_expected_degree_constraints(instr: Instruction, exp_degrees: HashMap<u64, usize>) {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigInt::from(0_usize))
    };
    interpreter::run_ivc(&mut constraints_fp, instr);

    let mut actual_degrees: HashMap<u64, usize> = HashMap::new();
    constraints_fp.constraints.iter().for_each(|c| {
        let degree = c.degree(1, 0);
        let count = actual_degrees.entry(degree).or_insert(0);
        *count += 1;
    });

    exp_degrees.iter().for_each(|(degree, count)| {
        assert_eq!(
            actual_degrees.get(degree),
            Some(count),
            "Instruction {:?}: invalid count for degree {} (computed: {}, expected: {})",
            instr,
            degree,
            actual_degrees.get(degree).unwrap(),
            count
        );
    });
}

// Helper to verify the number of columns each gadget uses
fn helper_gadget_number_of_columns_used(
    instr: Instruction,
    exp_nb_columns: usize,
    exp_nb_public_input: usize,
) {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigInt::from(0_usize))
    };
    interpreter::run_ivc(&mut constraints_fp, instr);

    let nb_columns = constraints_fp.idx_var;
    assert_eq!(nb_columns, exp_nb_columns);

    let nb_public_input = constraints_fp.idx_var_pi;
    assert_eq!(nb_public_input, exp_nb_public_input);
}

#[test]
fn test_gadget_poseidon() {
    let instr = Instruction::Poseidon(0);
    helper_compute_constraints_gadget(instr, 12);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(5, 12);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 15, 14);
}

#[test]
fn test_gadget_poseidon_next_row() {
    let instr = Instruction::PoseidonNextRow(0);
    helper_compute_constraints_gadget(instr, 15);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(5, 15);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 15, 17);

    // We always have 2 additional public inputs, even if set to 0
    let instr = Instruction::PoseidonNextRow(1);
    helper_gadget_number_of_columns_used(instr, 15, 17);
}

#[test]
fn test_gadget_sixteen_bits_decomposition() {
    let instr = Instruction::SixteenBitsDecomposition;
    helper_compute_constraints_gadget(instr, 1);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(1, 1);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 17, 0);
}

#[test]
fn test_gadget_bit_decomposition_from_16bits() {
    let instr = Instruction::BitDecompositionFrom16Bits(0);
    helper_compute_constraints_gadget(instr, 17);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(1, 1);
    exp_degrees.insert(2, 16);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 17, 0);
}

#[test]
fn test_gadget_elliptic_curve_addition() {
    let instr = Instruction::EllipticCurveAddition(0);
    helper_compute_constraints_gadget(instr, 3);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(3, 1);
    exp_degrees.insert(2, 2);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 8, 0);
}

#[test]
fn test_ivc_total_number_of_constraints_ivc() {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigInt::from(0_usize))
    };

    let ivc_instructions = [
        Instruction::PoseidonNextRow(0),
        Instruction::EllipticCurveAddition(0),
        Instruction::EllipticCurveScaling(0, 0),
    ];
    ivc_instructions.iter().for_each(|instr| {
        interpreter::run_ivc(&mut constraints_fp, *instr);
        constraints_fp.reset();
    });
    assert_eq!(constraints_fp.constraints.len(), 28);
}

#[test]
fn test_degree_of_constraints_ivc() {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigInt::from(0_usize))
    };
    let ivc_instructions = [
        Instruction::PoseidonNextRow(0),
        Instruction::EllipticCurveAddition(0),
        Instruction::EllipticCurveScaling(0, 0),
    ];

    ivc_instructions.iter().for_each(|instr| {
        interpreter::run_ivc(&mut constraints_fp, *instr);
        constraints_fp.reset();
    });

    let mut degree_per_constraints = HashMap::new();
    constraints_fp.constraints.iter().for_each(|c| {
        let degree = c.degree(1, 0);
        let count = degree_per_constraints.entry(degree).or_insert(0);
        *count += 1;
    });

    assert_eq!(degree_per_constraints.get(&1), Some(&1));
    assert_eq!(degree_per_constraints.get(&2), Some(&11));
    assert_eq!(degree_per_constraints.get(&3), Some(&1));
    assert_eq!(degree_per_constraints.get(&4), None);
    assert_eq!(degree_per_constraints.get(&5), Some(&15));
}

#[test]
fn test_gadget_elliptic_curve_scaling() {
    let instr = Instruction::EllipticCurveScaling(0, 0);
    // FIXME: update when the gadget is fnished
    helper_compute_constraints_gadget(instr, 10);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(1, 1);
    exp_degrees.insert(2, 9);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 10, 0);
}

#[test]
fn test_gadget_bit_decomposition() {
    let instr = Instruction::BitDecomposition(0);
    helper_compute_constraints_gadget(instr, 16);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(1, 1);
    exp_degrees.insert(2, 15);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 17, 0);
}
