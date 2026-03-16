#[cfg(feature = "prover")]
use super::framework::TestFramework;
#[cfg(feature = "prover")]
use crate::{
    circuits::{
        polynomials::generic::testing::{create_circuit, fill_in_witness},
        wires::COLUMNS,
    },
    proof::RecursionChallenge,
};
#[cfg(feature = "prover")]
use ark_ff::{UniformRand, Zero};
#[cfg(feature = "prover")]
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
#[cfg(feature = "prover")]
use core::array;
#[cfg(feature = "prover")]
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
#[cfg(feature = "prover")]
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
#[cfg(feature = "prover")]
use o1_utils::math;
#[cfg(feature = "prover")]
use poly_commitment::{commitment::b_poly_coefficients, SRS as _};

#[cfg(not(feature = "prover"))]
use super::generic::load_and_verify_fixture;

#[cfg(feature = "prover")]
type SpongeParams = PlonkSpongeConstantsKimchi;
#[cfg(feature = "prover")]
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
#[cfg(feature = "prover")]
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;

#[test]
fn test_recursion() {
    #[cfg(feature = "prover")]
    {
        let gates = create_circuit(0, 0);

        // create witness
        let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
        fill_in_witness(0, &mut witness, &[]);

        // setup
        let test_runner = TestFramework::<FULL_ROUNDS, Vesta>::default()
            .num_prev_challenges(1)
            .gates(gates)
            .witness(witness)
            .fixture_name("test_recursion")
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

    #[cfg(not(feature = "prover"))]
    load_and_verify_fixture(include_bytes!("fixtures/test_recursion.bin"));
}
