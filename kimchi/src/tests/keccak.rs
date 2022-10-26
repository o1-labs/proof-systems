use crate::circuits::{
    constraints::ConstraintSystem, gate::CircuitGate, polynomials::keccak::witness::create,
    wires::Wire,
};

use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};

type PallasField = <Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system() -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_keccak(0);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

#[test]
fn test_64bit_xor() {
    let cs = create_test_constraint_system();

    let zero_ones: u64 = 6510615555426900570;
    let one_zeros: u64 = 11936128518282651045;
    let witness = create(zero_ones, one_zeros);

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
