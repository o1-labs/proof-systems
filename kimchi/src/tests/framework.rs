//! Test Framework

use crate::circuits::lookup::tables::LookupTable;
use crate::circuits::polynomials::permutation::{zk_polynomial, zk_w3};
use crate::circuits::{gate::CircuitGate, wires::COLUMNS};
use crate::proof::ProverProof;
use crate::prover_index::testing::{new_index_for_test, new_index_for_test_with_lookups};
use crate::verifier::verify;
use crate::verifier_index::VerifierIndex;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use commitment_dlog::commitment::{b_poly_coefficients, CommitmentCurve};
use commitment_dlog::srs::SRS;
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
use std::sync::Arc;
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
            (chals, comm)
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

    /// Create and verify proof with deserialization
    pub(crate) fn run_test_serialization(
        gates: Vec<CircuitGate<Fp>>,
        witness: [Vec<Fp>; COLUMNS],
        public: &[Fp],
    ) {
        // create the index
        let start = Instant::now();
        let index = new_index_for_test(gates, public.len());
        let verifier_index = index.verifier_index();
        println!("- time to create index: {:?}s", start.elapsed().as_secs());

        let verifier_index_serialize =
            serde_json::to_string(&verifier_index).expect("couldn't serialize index");

        // verify the circuit satisfiability by the computed witness
        index.cs.verify(&witness, public).unwrap();

        // add the proof to the batch
        let start = Instant::now();
        let group_map = <Affine as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &index).unwrap();
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // deserialize the verifier index
        let mut verifier_index_deserialize: VerifierIndex<GroupAffine<VestaParameters>> =
            serde_json::from_str(&verifier_index_serialize).unwrap();

        // add srs with lagrange bases
        let mut srs = SRS::<GroupAffine<VestaParameters>>::create(verifier_index.max_poly_size);
        srs.add_lagrange_basis(verifier_index.domain);
        verifier_index_deserialize.srs = Arc::new(srs);
        verifier_index_deserialize.fq_sponge_params = oracle::pasta::fq_kimchi::params();
        verifier_index_deserialize.fr_sponge_params = oracle::pasta::fp_kimchi::params();
        verifier_index_deserialize.zkpm = zk_polynomial(verifier_index_deserialize.domain);
        verifier_index_deserialize.powers_of_alpha = index.powers_of_alpha;
        verifier_index_deserialize.linearization = index.linearization;
        verifier_index_deserialize.w = zk_w3(verifier_index_deserialize.domain);

        // verify the proof
        let start = Instant::now();
        verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index_deserialize, &proof)
            .unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }
}
