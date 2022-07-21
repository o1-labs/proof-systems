use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::foreign_field_mul::{self},
    wires::Wire,
};
use ark_ec::AffineCurve;
use ark_ff::Zero;
use mina_curves::pasta::pallas;
use o1_utils::foreign_field::{ForeignElement, FOREIGN_MOD};

type PallasField = <pallas::Affine as AffineCurve>::BaseField;

fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
    let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_foreign_field_mul(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates, oracle::pasta::fp_kimchi::params())
        .build()
        .unwrap()
}

#[test]
// Multiply zeroes. This checks that small amounts also get packed into limbs
fn test_zero_mul() {
    let cs = create_test_constraint_system();

    let foreign_modulus = ForeignElement::<PallasField, 3>::new_from_be(FOREIGN_MOD);

    let left_input = ForeignElement::<PallasField, 3>::new([
        PallasField::zero(),
        PallasField::zero(),
        PallasField::zero(),
    ]);
    let right_input = ForeignElement::<PallasField, 3>::new([
        PallasField::zero(),
        PallasField::zero(),
        PallasField::zero(),
    ]);

    let witness =
        foreign_field_mul::witness::create_witness(left_input, right_input, foreign_modulus);

    assert_eq!(
        cs.gates[20].verify_foreign_field_mul(0, &witness, &cs),
        Ok(())
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
