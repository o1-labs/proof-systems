use arrabbiata::{
    columns::Gadget,
    constraints,
    interpreter::{self, Instruction},
};
use mina_curves::pasta::{curves::vesta::Vesta, Pallas};
use std::collections::HashMap;

fn helper_compute_constraints_gadget(instr: Instruction, exp_constraints: usize) {
    let mut constraints_fp = constraints::Env::<Vesta>::new();

    interpreter::run_ivc(&mut constraints_fp, instr);
    assert_eq!(constraints_fp.constraints.len(), exp_constraints);

    let mut constraints_fq = constraints::Env::<Pallas>::new();
    interpreter::run_ivc(&mut constraints_fq, instr);
    assert_eq!(constraints_fq.constraints.len(), exp_constraints);
}

fn helper_check_expected_degree_constraints(instr: Instruction, exp_degrees: HashMap<u64, usize>) {
    let mut constraints_fp = constraints::Env::<Vesta>::new();
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
    let mut constraints_fp = constraints::Env::<Vesta>::new();
    interpreter::run_ivc(&mut constraints_fp, instr);

    let nb_columns = constraints_fp.idx_var;
    assert_eq!(nb_columns, exp_nb_columns);

    let nb_public_input = constraints_fp.idx_var_pi;
    assert_eq!(nb_public_input, exp_nb_public_input);
}

fn helper_check_gadget_activated(instr: Instruction, gadget: Gadget) {
    let mut constraints_fp = constraints::Env::<Vesta>::new();
    interpreter::run_ivc(&mut constraints_fp, instr);

    assert_eq!(constraints_fp.activated_gadget, Some(gadget));
}

#[test]
fn test_gadget_poseidon_next_row() {
    let instr = Instruction::Poseidon(0);
    helper_compute_constraints_gadget(instr, 15);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(5, 15);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 15, 17);

    // We always have 2 additional public inputs, even if set to 0
    let instr = Instruction::Poseidon(1);
    helper_gadget_number_of_columns_used(instr, 15, 17);

    helper_check_gadget_activated(instr, Gadget::Poseidon);
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

    helper_check_gadget_activated(instr, Gadget::EllipticCurveAddition);
}

#[test]
fn test_ivc_total_number_of_constraints_ivc() {
    let constraints_fp = constraints::Env::<Vesta>::new();

    let constraints = constraints_fp.get_all_constraints_for_ivc();
    assert_eq!(constraints.len(), 28);
}

#[test]
fn test_degree_of_constraints_ivc() {
    let constraints_fp = constraints::Env::<Vesta>::new();

    let constraints = constraints_fp.get_all_constraints_for_ivc();

    let mut degree_per_constraints = HashMap::new();
    constraints.iter().for_each(|c| {
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

    helper_check_gadget_activated(instr, Gadget::EllipticCurveScaling);
}
