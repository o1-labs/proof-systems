use num_bigint::BigUint;
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
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigUint::from(0_usize))
    };

    interpreter::run_ivc(&mut constraints_fp, instr);
    assert_eq!(constraints_fp.constraints.len(), exp_constraints);

    let mut constraints_fq = {
        let poseidon_mds = poseidon_3_60_0_5_5_fq::static_params().mds.clone();
        constraints::Env::<Fq>::new(poseidon_mds.to_vec(), BigUint::from(0_usize))
    };
    interpreter::run_ivc(&mut constraints_fq, instr);
    assert_eq!(constraints_fq.constraints.len(), exp_constraints);
}

#[test]
fn test_gadget_poseidon() {
    let instr = Instruction::Poseidon(0);
    helper_compute_constraints_gadget(instr, 12);
}

#[test]
fn test_gadget_sixteen_bits_decomposition() {
    let instr = Instruction::SixteenBitsDecomposition;
    helper_compute_constraints_gadget(instr, 1);
}

#[test]
fn test_gadget_bit_decomposition() {
    let instr = Instruction::BitDecompositionFrom16Bits(0);
    helper_compute_constraints_gadget(instr, 17);
}

#[test]
fn test_gadget_elliptic_curve_addition() {
    let instr = Instruction::EllipticCurveAddition(0);
    helper_compute_constraints_gadget(instr, 3);
}

#[test]
fn test_ivc_total_number_of_constraints_ivc() {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigUint::from(0_usize))
    };

    let ivc_instructions = [
        Instruction::Poseidon(0),
        Instruction::SixteenBitsDecomposition,
        Instruction::BitDecompositionFrom16Bits(0),
        Instruction::EllipticCurveAddition(0),
    ];
    ivc_instructions.iter().for_each(|instr| {
        interpreter::run_ivc(&mut constraints_fp, *instr);
        constraints_fp.reset();
    });
    assert_eq!(constraints_fp.constraints.len(), 33);
}

#[test]
fn test_degree_of_constraints_ivc() {
    let mut constraints_fp = {
        let poseidon_mds = poseidon_3_60_0_5_5_fp::static_params().mds.clone();
        constraints::Env::<Fp>::new(poseidon_mds.to_vec(), BigUint::from(0_usize))
    };
    let ivc_instructions = [
        Instruction::Poseidon(0),
        Instruction::SixteenBitsDecomposition,
        Instruction::BitDecompositionFrom16Bits(0),
        Instruction::EllipticCurveAddition(0),
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

    assert_eq!(degree_per_constraints.get(&1), Some(&2));
    assert_eq!(degree_per_constraints.get(&2), Some(&18));
    assert_eq!(degree_per_constraints.get(&3), Some(&1));
    assert_eq!(degree_per_constraints.get(&4), None);
    assert_eq!(degree_per_constraints.get(&5), Some(&12));
}