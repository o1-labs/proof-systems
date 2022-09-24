use super::framework::TestFramework;
use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::COLUMNS;
use ark_ff::Zero;
use mina_curves::pasta::Fp;
use std::array;

#[test]
fn test_generic_gate() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &[]);

    // create and verify proof based on the witness
    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify();
}

#[test]
fn test_generic_gate_pub() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify();
}

#[test]
fn test_generic_gate_pub_all_zeros() {
    let public = vec![Fp::from(0u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify();
}

#[test]
fn test_generic_gate_pub_empty() {
    let public = vec![];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify();
}
