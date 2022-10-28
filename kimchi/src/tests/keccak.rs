use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::keccak::{witness::create_rot, ROT_TAB},
    wires::Wire,
};

use mina_curves::pasta::{Fp, Vesta};

fn create_test_constraint_system(x: usize, y: usize) -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = { CircuitGate::<Fp>::create_keccak_rot(0, x, y) };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::new(next_row)));
        next_row += 1;
    }

    ConstraintSystem::create(gates).build().unwrap()
}

#[test]
fn test_rot_table() {
    let (x, y) = (4, 3);
    let cs = create_test_constraint_system(x, y);
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
