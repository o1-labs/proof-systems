use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        polynomial::COLUMNS,
        polynomials::{generic::GenericGateSpec, keccak::witness::create_witness},
        wires::{Wire, PERMUTS},
    },
    proof::ProverProof,
    prover_index::testing::new_index_for_test_with_lookups,
};

use ark_ec::AffineCurve;
use mina_curves::pasta::{pallas, vesta::Vesta, Fp};

use std::array;

type PallasField = <pallas::Pallas as AffineCurve>::BaseField;

fn create_test_constraint_system() -> ConstraintSystem<Fp> {
    let (mut next_row, mut gates) = CircuitGate::<Fp>::create_keccak_xor(0);

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

    let all_ones: u64 = (2u128.pow(64) - 1) as u64;
    let witness = create_witness(all_ones, all_ones);

    /*     for row in 0..=7 {
            println!("row: {}", row);
            for col in 0..PERMUTS {
                println!("col {} connected to {:?}", col, cs.gates[row].wires[col]);
            }
        }
    */
    for row in 0..=7 {
        println!("verify row: {}", row);
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
