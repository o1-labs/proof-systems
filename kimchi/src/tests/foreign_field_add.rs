use crate::circuits::gate::CircuitGateError;
use crate::circuits::polynomials::foreign_field_add::{self};
use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        constraints::ConstraintSystem,
        domains::EvaluationDomains,
        expr::{self, l0_1, Environment, LookupEnvironment, E},
        gate::{CircuitGate, GateType},
        lookup::{
            self,
            lookups::LookupsUsed,
            tables::{GateLookupTable, LookupTable},
        },
        polynomial::COLUMNS,
        polynomials::range_check,
        wires::{GateWires, Wire},
    },
};
use crate::{
    circuits::lookup::lookups::LookupInfo,
    prover_index::{testing::new_index_for_test_with_lookups, ProverIndex},
};
use ark_ec::AffineCurve;
use ark_ff::{FftField, Field, One, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use mina_curves::pasta::pallas;
use num_bigint::BigUint;
use o1_utils::{
    foreign_field::{foreign_to_limbs, vec_to_limbs, FOREIGN_MOD},
    FieldHelpers,
};

type PallasField = <pallas::Affine as AffineCurve>::BaseField;

fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_foreign_field_add(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates, oracle::pasta::fp_kimchi::params())
        .build()
        .unwrap()
}

fn create_test_prover_index(public_size: usize) -> ProverIndex<mina_curves::pasta::vesta::Affine> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_multi_range_check(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    new_index_for_test_with_lookups(gates, public_size, vec![range_check::lookup_table()], None)
}

#[test]
// Add zero to zero. This checks that small amounts also get packed into limbs
fn test_zero_add() {
    let cs = create_test_constraint_system();
    let foreign_modulus = vec_to_limbs(&foreign_to_limbs(BigUint::from_bytes_be(FOREIGN_MOD)));
    let left_input = [
        PallasField::zero(),
        PallasField::zero(),
        PallasField::zero(),
    ];
    let right_input = [
        PallasField::zero(),
        PallasField::zero(),
        PallasField::zero(),
    ];

    let witness =
        foreign_field_add::witness::create_witness(&left_input, &right_input, &foreign_modulus);

    assert_eq!(
        cs.gates[16].verify_foreign_field_add(0, &witness, &cs),
        Err(CircuitGateError::InvalidConstraint(
            GateType::ForeignFieldAdd
        ))
    );
}

#[test]
fn test_zero_sum() {}

#[test]
fn test_max_number() {}

#[test]
fn test_pos_plus_pos() {}

#[test]
fn test_pos_plus_neg() {}

#[test]
fn test_neg_plus_pos() {}

#[test]
fn test_neg_plus_neg() {}

#[test]
fn test_no_carry_limbs() {}

#[test]
fn test_carry_limb_lo() {}

#[test]
fn test_carry_limb_mid() {}

#[test]
fn test_carry_limb_hi() {}

#[test]
fn test_carry_limb_lo_mid() {}

#[test]
fn test_carry_limb_lo_hi() {}

#[test]
fn test_carry_limb_mid_hi() {}

#[test]
fn test_carry_limb_lo_mid_hi() {}

#[test]
fn test_wrong_sum_should_fail() {}

#[test]
fn test_larger_result_should_fail() {}

#[test]
fn test_larger_addends_should_fail() {}
