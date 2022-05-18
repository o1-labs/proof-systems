use super::framework::TestFramework;
use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::COLUMNS;
use ark_ff::Zero;
use array_init::array_init;
use mina_curves::pasta::fp::Fp;

#[test]
fn test_recursion() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &[]);

    TestFramework::run_test_recursion(gates, witness, &[]);
}
