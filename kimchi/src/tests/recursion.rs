use super::framework::TestFramework;
use crate::{
    circuits::{
        polynomials::generic::testing::{create_circuit, fill_in_witness},
        wires::COLUMNS,
    },
    proof::RecursionChallenge,
};
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use core::array;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::math;
use poly_commitment::{commitment::b_poly_coefficients, SRS as _};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, 55>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, 55>;

#[test]
fn test_recursion() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &[]);

    // setup
    let test_runner = TestFramework::<55, Vesta>::default()
        .num_prev_challenges(1)
        .gates(gates)
        .witness(witness)
        .setup();

    // previous opening for recursion
    let index = test_runner.prover_index();
    let rng = &mut o1_utils::tests::make_test_rng(None);
    let prev_challenges = {
        let k = math::ceil_log2(index.srs.g.len());
        let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
        let comm = {
            let coeffs = b_poly_coefficients(&chals);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.commit_non_hiding(&b, 1)
        };
        RecursionChallenge::new(chals, comm)
    };

    test_runner
        .recursion(vec![prev_challenges])
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}
