use super::framework::TestFramework;
use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::COLUMNS;
use ark_ff::Zero;
use array_init::array_init;
use mina_curves::pasta::fp::Fp;

#[test]
fn test_generic_gate() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
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
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify();
}
