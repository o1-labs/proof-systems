use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::{keccak::ROT_TAB, rot},
    wires::Wire,
};
use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use rand::Rng;

use super::framework::TestFramework;
type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system(rot: u32) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = { CircuitGate::<Fp>::create_rot(0, rot) };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

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
}

#[test]
// Test that all of the offsets in the rotation table work fine
fn test_rot_table() {
    for x in 0..5 {
        for y in 0..5 {
            let rot = ROT_TAB[x][y];
            if rot == 0 {
                // skip the zero rotation
                continue;
            }
            let cs = create_test_constraint_system(rot);
            let word = 0x0123456789ABCDEF;
            let witness = rot::create_witness_rot(word, rot);
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
            assert_eq!(
                PallasField::from(word.rotate_left(ROT_TAB[x][y])),
                witness[1][1],
            );
        }
    }
}
