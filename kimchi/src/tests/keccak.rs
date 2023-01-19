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
// Test rounds of Keccak
fn test_keccak_rounds() {
    // hash the 0 bit
    let hash = keccak::keccak_eth(&[0x00]);
    println!();
    for byte in hash {
        print!("{:02x}", byte);
    }
    println!();
}

#[test]
// Test if converters work fine
fn test_from() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let bytes = (0..STATE / 8)
        .map(|_| rng.gen_range(0..=255))
        .collect::<Vec<u8>>();
    let converted = keccak::from_state_to_le(keccak::from_le_to_state(&bytes));
    assert_eq!(bytes, converted);
}

#[test]
// Check that the padding is added in little endian
fn test_padding() {
    let message = 0x01;
    // 0x01 0x01 0x00 ... 0x00 0x80
    let padded = keccak::pad(&[message], 1088);
    let number = BigUint::from_bytes_be(&padded);
    let desired =
        BigUint::from(2u8).pow(1080) + BigUint::from(2u8).pow(1072) + BigUint::from(2u32.pow(7));
    assert_eq!(number, desired)
}
