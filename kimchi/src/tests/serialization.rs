use super::framework::TestFramework;
use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::COLUMNS;
use ark_ff::Zero;
use array_init::array_init;
use mina_curves::pasta::fp::Fp;

#[test]
pub fn test_serialization() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::run_test_serialization(gates, witness, &public);
}
