use super::framework::TestFramework;
use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::COLUMNS;
use crate::proof::RecursionChallenge;
use ark_ff::{UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use commitment_dlog::commitment::b_poly_coefficients;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::math;
use rand::prelude::*;
use std::array;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[test]
fn test_recursion() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &[]);

    // setup
    let test_runner = TestFramework::<Vesta>::default()
        .num_prev_challenges(1)
        .gates(gates)
        .witness(witness)
        .setup();

    // previous opening for recursion
    let index = test_runner.prover_index();
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let prev_challenges = {
        let k = math::ceil_log2(index.srs.g.len());
        let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
        let comm = {
            let coeffs = b_poly_coefficients(&chals);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.commit_non_hiding(&b, None)
        };
        RecursionChallenge::new(chals, comm)
    };

    assert!(test_runner
        .recursion(vec![prev_challenges])
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .is_ok());
}
