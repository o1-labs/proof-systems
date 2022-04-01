use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::{gate::CircuitGate, wires::COLUMNS};
use crate::proof::ProverProof;
use crate::prover_index::testing::new_index_for_test;
use crate::verifier::verify;
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::commitment::{b_poly_coefficients, CommitmentCurve};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::{rngs::StdRng, SeedableRng};

use o1_utils::math;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[test]
fn test_generic_gate() {
    let gates = create_circuit(0, 0);

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &[]);

    // create and verify proof based on the witness
    verify_proof(gates, witness, &[]);
}

#[test]
fn test_generic_gate_pub() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    verify_proof(gates, witness, &public);
}

fn verify_proof(gates: Vec<CircuitGate<Fp>>, witness: [Vec<Fp>; COLUMNS], public: &[Fp]) {
    // set up
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    // create the index
    let index = new_index_for_test(gates, vec![], public.len());

    // verify the circuit satisfiability by the computed witness
    index.cs.verify(&witness, public).unwrap();

    // previous opening for recursion
    let prev = {
        let k = math::ceil_log2(index.srs.g.len());
        let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
        let comm = {
            let coeffs = b_poly_coefficients(&chals);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.commit_non_hiding(&b, None)
        };
        (chals, comm)
    };

    // add the proof to the batch
    let proof = ProverProof::create_recursive::<BaseSponge, ScalarSponge>(
        &group_map,
        witness,
        &index,
        vec![prev],
    )
    .unwrap();

    // verify the proof
    let verifier_index = index.verifier_index();
    verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof).unwrap();
}
