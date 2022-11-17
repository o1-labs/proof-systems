use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::rot::{self, LEFT, RIGHT},
    wires::Wire,
};
use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use rand::Rng;

//use super::framework::TestFramework;
type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system(rot: u32, side: bool) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = { CircuitGate::<Fp>::create_rot(0, rot, side) };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}
/* TODO: STILL DOES NOT WORK WITH COEFFICIENTS
// Function to create a prover and verifier to test the XOR circuit
fn prove_and_verify() {
    let rot = rand::thread_rng().gen_range(1..64);
    // Create
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_rot(0, rot);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    // Create input
    let word = rand::thread_rng().gen_range(0..2u128.pow(64)) as u64;

    // Create witness
    let witness = rot::create_witness_rot(word, rot);

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify();
}

#[test]
// End-to-end test
fn test_prove_and_verify() {
    prove_and_verify();
}*/

fn test_rot(word: u64, rot: u32, side: bool) {
    let cs = create_test_constraint_system(rot, side);
    let witness = rot::create_witness(word, rot, side);
    for row in 0..=2 {
        assert_eq!(
            cs.gates[row].verify_witness::<Vesta>(
                row,
                &witness,
                &cs,
                &witness[0][0..cs.public].to_vec()
            ),
            Ok(())
        );
    }
    if side == LEFT {
        assert_eq!(PallasField::from(word.rotate_left(rot)), witness[1][1]);
    } else {
        assert_eq!(PallasField::from(word.rotate_right(rot)), witness[1][1]);
    }
}

#[test]
// Test that a random offset between 1 and 63 work as expected, both left and right
fn test_rot_random() {
    let rot = rand::thread_rng().gen_range(1..=63);
    let word = rand::thread_rng().gen_range(0..2u128.pow(64)) as u64;
    test_rot(word, rot, LEFT);
    test_rot(word, rot, RIGHT);
}
