use crate::{index::Index, prover::ProverProof};
use ark_ff::{One, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use kimchi_circuits::{
    gate::CircuitGate,
    nolookup::constraints::ConstraintSystem,
    wires::{Wire, COLUMNS},
};
use mina_curves::pasta::vesta::VestaParameters;
use mina_curves::pasta::{fp::Fp, pallas::Affine as Other, vesta::Affine};
use oracle::{
    poseidon::PlonkSpongeConstants15W,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const MUL_GATES: usize = 1000;
const ADD_GATES: usize = 1000;

const LEFT: usize = 0;
const RIGHT: usize = 1;
const OUTPUT: usize = 2;

/// Produces `num` proofs and verifies them one by one.
pub fn proof(num: usize) {
    // create the circuit
    let mut gates = vec![];
    let mut abs_row = 0;

    for _ in 0..MUL_GATES {
        let wires = Wire::new(abs_row);
        gates.push(CircuitGate::<Fp>::create_generic_mul(abs_row, wires));
        abs_row += 1;
    }

    for _ in 0..ADD_GATES {
        let wires = Wire::new(abs_row);
        gates.push(CircuitGate::create_generic_add(
            abs_row,
            wires,
            Fp::one(),
            Fp::one(),
        ));
        abs_row += 1;
    }

    // set up
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    // create the index
    let fp_sponge_params = oracle::pasta::fp::params();
    let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, 0).unwrap();
    let n = cs.domain.d1.size as usize;
    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let mut srs = SRS::create(n);
    srs.add_lagrange_basis(cs.domain.d1);
    let srs = Arc::new(srs);
    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    for _ in 0..num {
        // create witness
        let mut witness: [Vec<Fp>; COLUMNS] =
            array_init(|_| vec![Fp::zero(); MUL_GATES + ADD_GATES]);

        for row in 0..MUL_GATES {
            witness[LEFT][row] = 3u32.into();
            witness[RIGHT][row] = 5u32.into();
            witness[OUTPUT][row] = Fp::from(3u32 * 5);
        }

        for row in MUL_GATES..MUL_GATES + ADD_GATES {
            witness[LEFT][row] = 3u32.into();
            witness[RIGHT][row] = 5u32.into();
            witness[OUTPUT][row] = Fp::from(3u32 + 5);
        }

        // previous opening for recursion
        let prev = {
            let k = ceil_log2(index.srs.g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let coeffs = b_poly_coefficients(&chals);
                let b = DensePolynomial::from_coefficients_vec(coeffs);
                index.srs.commit_non_hiding(&b, None)
            };
            (chals, comm)
        };

        // add the proof to the batch
        let mut batch = Vec::new();
        batch.push(
            ProverProof::create::<BaseSponge, ScalarSponge>(
                &group_map,
                witness,
                vec![],
                &index,
                vec![prev],
            )
            .unwrap(),
        );

        // verify the proof
        let verifier_index = index.verifier_index();
        let lgr_comms = vec![];
        let batch: Vec<_> = batch
            .iter()
            .map(|proof| (&verifier_index, &lgr_comms, proof))
            .collect();
        ProverProof::verify::<BaseSponge, ScalarSponge>(&group_map, &batch).unwrap();
    }
}
