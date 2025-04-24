use arrabbiata::{
    column::E,
    constraint,
    interpreter::{self, Instruction},
    MAX_DEGREE, NUMBER_OF_COLUMNS,
};
use mina_curves::pasta::{curves::vesta::Vesta, Fp, Pallas};
use mvpoly::{monomials::Sparse, MVPoly};
use std::collections::HashMap;

fn helper_compute_constraints_gadget(instr: Instruction, exp_constraints: usize) {
    let mut constraints_fp = constraint::Env::<Vesta>::new();

    interpreter::run_ivc(&mut constraints_fp, instr);
    assert_eq!(constraints_fp.constraints.len(), exp_constraints);

    let mut constraints_fq = constraint::Env::<Pallas>::new();
    interpreter::run_ivc(&mut constraints_fq, instr);
    assert_eq!(constraints_fq.constraints.len(), exp_constraints);
}

fn helper_check_expected_degree_constraints(instr: Instruction, exp_degrees: HashMap<u64, usize>) {
    let mut constraints_fp = constraint::Env::<Vesta>::new();
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
fn helper_gadget_number_of_columns_used(instr: Instruction, exp_nb_columns: usize) {
    let mut constraints_fp = constraint::Env::<Vesta>::new();
    interpreter::run_ivc(&mut constraints_fp, instr);

    let nb_columns = constraints_fp.idx_var;
    assert_eq!(nb_columns, exp_nb_columns);
}

#[test]
fn test_gadget_elliptic_curve_addition() {
    let instr = Instruction::EllipticCurveAddition(0);
    helper_compute_constraints_gadget(instr, 3);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(3, 1);
    exp_degrees.insert(2, 2);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 8);
}

#[test]
fn test_ivc_total_number_of_constraints_ivc() {
    let constraints_fp = constraint::Env::<Vesta>::new();

    let constraints = constraints_fp.get_all_constraints_for_verifier();
    assert_eq!(constraints.len(), 90);
}

#[test]
fn test_degree_of_constraints_ivc() {
    let constraints_fp = constraint::Env::<Vesta>::new();

    let constraints = constraints_fp.get_all_constraints_for_verifier();

    let mut degree_per_constraints = HashMap::new();
    constraints.iter().for_each(|c| {
        let degree = c.degree(1, 0);
        let count = degree_per_constraints.entry(degree).or_insert(0);
        *count += 1;
    });

    assert_eq!(degree_per_constraints.get(&1), Some(&3));
    assert_eq!(degree_per_constraints.get(&2), Some(&11));
    assert_eq!(degree_per_constraints.get(&3), Some(&1));
    assert_eq!(degree_per_constraints.get(&4), None);
    assert_eq!(degree_per_constraints.get(&5), Some(&75));
}

#[test]
fn test_gadget_elliptic_curve_scaling() {
    let instr = Instruction::EllipticCurveScaling(0, 0);
    helper_compute_constraints_gadget(instr, 10);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(1, 1);
    exp_degrees.insert(2, 9);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 10);
}

#[test]
fn test_gadget_poseidon_permutation() {
    let instr = Instruction::PoseidonFullRound(0);
    helper_compute_constraints_gadget(instr, 15);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(5, 15);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 15);
}

#[test]
fn test_gadget_poseidon_sponge_absorb() {
    let instr = Instruction::PoseidonSpongeAbsorb;
    // Only two addition constraints
    helper_compute_constraints_gadget(instr, 2);

    let mut exp_degrees = HashMap::new();
    exp_degrees.insert(1, 2);
    helper_check_expected_degree_constraints(instr, exp_degrees);

    helper_gadget_number_of_columns_used(instr, 6);
}

#[test]
fn test_get_mvpoly_equivalent() {
    // Check that each constraint can be converted to a MVPoly. The type of the
    // MVPoly is crucial as it determines the maximum degree of the constraint
    // and the number of wires. For this reason, no check is performed on the
    // result of the mapping.
    let constraints_fp: Vec<E<Fp>> = {
        let constraints_env: constraint::Env<Vesta> = constraint::Env::default();
        constraints_env.get_all_constraints()
    };
    let _constraints_fp: Vec<Sparse<Fp, { NUMBER_OF_COLUMNS * 2 }, { MAX_DEGREE }>> =
        constraints_fp
            .into_iter()
            .map(|expr| Sparse::from_expr(expr, Some(NUMBER_OF_COLUMNS)))
            .collect();
}
