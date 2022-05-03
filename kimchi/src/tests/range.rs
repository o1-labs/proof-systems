use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::wires::Wire;
use crate::circuits::{gate::CircuitGate, wires::COLUMNS};
use crate::proof::ProverProof;
use crate::prover_index::testing::new_index_for_test;
use crate::verifier::verify;
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::commitment::{b_poly_coefficients, CommitmentCurve};
use groupmap::GroupMap;
use itertools::iterate;
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
fn test_range_gate() {
    let mut gates = vec![];
    let mut gates_row = iterate(0, |&i| i + 1);
    let mut row = || gates_row.next().unwrap();

    // public input
    for _ in 0..5 {
        gates.push(CircuitGate::create_range(Wire::new(row())));
    }

    // create BAD witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    witness[0][0] = Fp::from((1 << 13) as u32);

    // create and verify proof based on the witness
    // create the index
    let index = new_index_for_test(gates, 0);

    // add the proof to the batch
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, None, &index).unwrap();

    // verify the proof
    let verifier_index = index.verifier_index();

    verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof).unwrap();
}
