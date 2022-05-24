//! Test Framework

use crate::circuits::lookup::tables::LookupTable;
use crate::circuits::{gate::CircuitGate, wires::COLUMNS};
use crate::proof::{Challenge, ProverProof};
use crate::prover_index::testing::{new_index_for_test, new_index_for_test_with_lookups};
use crate::verifier::verify;
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use commitment_dlog::commitment::{b_poly_coefficients, CommitmentCurve};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Affine, VestaParameters},
};
use o1_utils::math;
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::prelude::*;
use std::time::Instant;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

/// TKTK
pub(crate) struct TestFramework;

impl TestFramework {
    /// Create and verify a proof
    pub(crate) fn run_test(
        gates: Vec<CircuitGate<Fp>>,
        witness: [Vec<Fp>; COLUMNS],
        public: &[Fp],
    ) {
        // create the index
        let start = Instant::now();
        let index = new_index_for_test(gates, public.len());
        let verifier_index = index.verifier_index();
        println!("- time to create index: {:?}s", start.elapsed().as_secs());

        // verify the circuit satisfiability by the computed witness
        index.cs.verify(&witness, public).unwrap();

        // add the proof to the batch
        let start = Instant::now();
        let group_map = <Affine as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &index).unwrap();
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof
        let start = Instant::now();
        verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof).unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }

    /// Create and verify a recursive proof
    pub(crate) fn run_test_recursion(
        gates: Vec<CircuitGate<Fp>>,
        witness: [Vec<Fp>; COLUMNS],
        public: &[Fp],
    ) {
        // create the index
        let start = Instant::now();
        let index = new_index_for_test(gates, public.len());
        let verifier_index = index.verifier_index();
        println!("- time to create index: {:?}s", start.elapsed().as_secs());

        // verify the circuit satisfiability by the computed witness
        index.cs.verify(&witness, public).unwrap();

        // previous opening for recursion
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let prev_challenges = {
            let k = math::ceil_log2(index.srs.g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let coeffs = b_poly_coefficients(&chals);
                let b = DensePolynomial::from_coefficients_vec(coeffs);
                index.srs.commit_non_hiding(&b, None)
            };
            Challenge { chals, comm }
        };

        // add the proof to the batch
        let start = Instant::now();
        let group_map = <Affine as CommitmentCurve>::Map::setup();
        let proof = ProverProof::create_recursive::<BaseSponge, ScalarSponge>(
            &group_map,
            witness,
            &index,
            vec![prev_challenges],
        )
        .unwrap();
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof
        let start = Instant::now();
        verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof).unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }

    /// Create and verify a proof with lookup tables
    pub(crate) fn run_test_lookups(
        gates: Vec<CircuitGate<Fp>>,
        witness: [Vec<Fp>; COLUMNS],
        public: &[Fp],
        lookup_tables: Vec<LookupTable<Fp>>,
    ) {
        // create the index
        let start = Instant::now();
        let index = new_index_for_test_with_lookups(gates, public.len(), lookup_tables);
        let verifier_index = index.verifier_index();
        println!("- time to create index: {:?}s", start.elapsed().as_secs());

        // verify the circuit satisfiability by the computed witness
        index.cs.verify(&witness, public).unwrap();

        // add the proof to the batch
        let start = Instant::now();
        let group_map = <Affine as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &index).unwrap();
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof
        let start = Instant::now();
        verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof).unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }
}
