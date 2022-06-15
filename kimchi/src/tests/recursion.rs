use super::framework::TestFramework;
use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::COLUMNS;
use crate::proof::RecursionChallenge;
use ark_ff::{UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use array_init::array_init;
use commitment_dlog::commitment::b_poly_coefficients;
use mina_curves::pasta::fp::Fp;
use rand::prelude::*;

#[test]
fn test_recursion() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &[]);

    // setup
    let recursive_proofs = vec![2, 4];
    let test_runner = TestFramework::default()
        .gates(gates)
        .witness(witness)
        .recursive_proofs(recursive_proofs.clone())
        .setup();

    // previous opening for recursion
    let index = test_runner.prover_index();
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let mut prev_challenges = vec![];
    for k in recursive_proofs {
        let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
        let comm = {
            let coeffs = b_poly_coefficients(&chals);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.commit_non_hiding(&b, None)
        };
        prev_challenges.push(RecursionChallenge::new(chals, comm));
    }

    test_runner.recursion(prev_challenges).prove_and_verify();
}
