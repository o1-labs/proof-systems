use std::array;

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::keccak::{self, ROT_TAB, STATE},
    wires::Wire,
};
use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use num_bigint::BigUint;
use rand::{rngs::StdRng, Rng, SeedableRng};

//use super::framework::TestFramework;
type PallasField = <Pallas as AffineCurve>::BaseField;

const RNG_SEED: [u8; 32] = [
    0, 131, 43, 175, 229, 252, 206, 26, 67, 193, 86, 160, 1, 90, 131, 86, 168, 4, 95, 50, 48, 9,
    192, 13, 250, 215, 172, 130, 24, 164, 162, 221,
];

fn create_test_constraint_system() -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = { CircuitGate::<Fp>::create_keccak(0) };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

#[test]
// Test that all of the offsets in the rotation table work fine
fn test_keccak_table() {
    let cs = create_test_constraint_system();
    let state = array::from_fn(|_| {
        array::from_fn(|_| rand::thread_rng().gen_range(0..2u128.pow(64)) as u64)
    });
    let witness = keccak::create_witness_keccak_rot(state);
    for row in 0..=48 {
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
    let mut rot = 0;
    for (x, row) in ROT_TAB.iter().enumerate() {
        for (y, &bits) in row.iter().enumerate() {
            if bits == 0 {
                continue;
            }
            assert_eq!(
                PallasField::from(state[x][y].rotate_left(bits)),
                witness[1][1 + 2 * rot],
            );
            rot += 1;
        }
    }
}

#[test]
// Test if converters work fine
fn test_from() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let bytes = (0..STATE / 8)
        .map(|_| rng.gen_range(0..=255))
        .collect::<Vec<u8>>();
    let converted = keccak::from_state_to_bytes(keccak::from_bytes_to_state(&bytes));
    assert_eq!(bytes, converted);
}

#[test]
// Check that the padding is added correctly
fn test_padding() {
    let message = 0x30; // Character "0"
    let bytes = [0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
    // 0x30 0x01 0x00 ... 0x00 0x80
    let padded = keccak::pad(&[message], 1088);
    let number = BigUint::from_bytes_be(&padded);
    let desired = BigUint::from_bytes_be(&bytes);
    assert_eq!(number, desired)
}

#[test]
// Check the steps of the hash
fn test_f() {
    let message = [0x33u8, 0x0A, 0x84, 0x2A, 0xEE, 0x90, 0x73, 0xFD, 0x85, 0x21]; // Character "0"
    let hash = keccak::keccak_eth(&message);
    let desired = [0x36, 0x3d, 0xf8, 0xb0, 0x53, 0x90, 0x94, 0xb1, 0x3d, 0x45, 0x6a, 0x5c, 0xb4, 0xc0, 0xe2, 0x18, 0x05, 0xc6, 0x3c, 0xc5, 0x78, 0x13, 0x06, 0x57, 0xc7, 0x61, 0x6d, 0xf5, 0xc8, 0x5a, 0x8d, 0x52];
    assert_eq!(hash, desired);
}