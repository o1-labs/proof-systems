use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::keccak::{
        witness::{create_rot, create_xor},
        ROT_TAB,
    },
    wires::Wire,
};

use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use rand::Rng;

type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system(
    str: String,
    coord: Option<(usize, usize)>,
) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = {
        if str == "xor" {
            CircuitGate::<Fp>::create_keccak_xor(0)
        } else if str == "rot" {
            CircuitGate::<Fp>::create_keccak_rot(0, coord.unwrap().0, coord.unwrap().1)
        } else {
            panic!("Invalid string");
        }
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

#[test]
// Test a XOR of 64bit whose output is all ones with alternating inputs
fn test_xor64_alternating() {
    let cs = create_test_constraint_system("xor".to_string(), None);

    let zero_ones: u64 = 6510615555426900570;
    let one_zeros: u64 = 11936128518282651045;
    let witness = create_xor(zero_ones, one_zeros);

    for row in 0..=5 {
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

    assert_eq!(witness[2][1], PallasField::from(2u128.pow(64) - 1));
    assert_eq!(witness[2][2], PallasField::from(2u64.pow(48) - 1));
    assert_eq!(witness[2][3], PallasField::from(2u64.pow(32) - 1));
    assert_eq!(witness[2][4], PallasField::from(2u32.pow(16) - 1));
    assert_eq!(witness[2][5], PallasField::from(0));
}

#[test]
// Test a XOR of 64bit whose inputs are zero. Checks it works fine with non-dense values.
fn test_xor64_zeros() {
    let cs = create_test_constraint_system("xor".to_string(), None);

    let zero: u64 = 0;
    let witness = create_xor(zero, zero);

    for row in 0..=5 {
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
    assert_eq!(witness[2][1], PallasField::from(zero));
}

#[test]
// Test a XOR of 64bit whose inputs are all zero and all one. Checks it works fine with non-dense values.
fn test_xor64_zero_one() {
    let cs = create_test_constraint_system("xor".to_string(), None);

    let zero: u64 = 0;
    let all_ones: u64 = (2u128.pow(64) - 1) as u64;
    let witness = create_xor(zero, all_ones);

    for row in 0..=5 {
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
    assert_eq!(witness[2][1], PallasField::from(all_ones));
}

#[test]
// Tests a XOR of 64 bits for a random input
fn test_xor64_random() {
    let cs = create_test_constraint_system("xor".to_string(), None);

    let input1 = rand::thread_rng().gen_range(0..(2u128.pow(64) - 1)) as u64;
    let input2 = rand::thread_rng().gen_range(0..(2u128.pow(64) - 1)) as u64;
    let output = input1 ^ input2;
    let witness = create_xor(input1, input2);

    for row in 0..=5 {
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
    assert_eq!(witness[2][1], PallasField::from(output));
}

#[test]
fn test_rot_table() {
    let (x, y) = (4, 3);
    let cs = create_test_constraint_system("rot".to_string(), Some((x, y)));
    let word = 0x0123456789ABCDEF;
    let rot = ROT_TAB[x][y]; // rotate by 61
    let witness = create_rot(word, rot);
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
}
