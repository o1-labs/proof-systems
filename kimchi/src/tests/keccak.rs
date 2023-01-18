use std::array;

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::keccak::{self, ROT_TAB, STATE_WIDTH},
    wires::Wire,
};
use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
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
    let hash = keccak::keccak_hash(&[false]);
    for byte in hash {
        print!("{:02x}", byte);
    }
    println!();
}

#[test]
// Test if converters work fine
fn test_from() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let bits: Vec<bool> = (0..STATE_WIDTH).map(|_| rng.gen_range(0..2) != 0).collect();
    let converted = keccak::from_state_to_bits(keccak::from_bits_to_state(&bits));
    assert_eq!(bits, converted);
}
