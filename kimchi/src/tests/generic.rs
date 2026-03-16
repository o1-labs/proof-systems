#[cfg(feature = "prover")]
use super::framework::TestFramework;
#[cfg(feature = "prover")]
use crate::circuits::{
    polynomials::generic::testing::{create_circuit, fill_in_witness},
    wires::COLUMNS,
};
#[cfg(feature = "prover")]
use ark_ff::Zero;
#[cfg(feature = "prover")]
use core::array;

use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

#[cfg(not(feature = "prover"))]
use mina_curves::pasta::{Fq, Pallas, PallasParameters};

#[cfg(not(feature = "prover"))]
use {
    super::fixtures::RawFixture,
    crate::{
        linearization::expr_linearization, proof::ProverProof,
        verifier::verify_with_rng, verifier_index::VerifierIndex,
    },
    alloc::{sync::Arc, vec::Vec},
    ark_serialize::CanonicalDeserialize,
    groupmap::GroupMap,
    poly_commitment::{
        commitment::CommitmentCurve,
        ipa::{endos, OpeningProof, SRS},
        SRS as SrsTrait,
    },
};

#[cfg(feature = "bn254")]
mod kzg {
    pub(super) use ark_bn254::{g1::Config as Bn254G1Config, Fr};
    pub(super) use ark_ec::bn::Bn;
    pub(super) use poly_commitment::{
        kzg::{KZGProof, PairingSRS},
        SRS,
    };
}
#[cfg(feature = "bn254")]
use kzg::*;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge<P> = DefaultFqSponge<P, SpongeParams, FULL_ROUNDS>;
type ScalarSponge<Fr> = DefaultFrSponge<Fr, SpongeParams, FULL_ROUNDS>;

#[cfg(not(feature = "prover"))]
pub(super) fn load_and_verify_fixture(fixture_bytes: &[u8]) {
    let fixture: RawFixture = rmp_serde::from_slice(fixture_bytes).unwrap();
    let proof: ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS> =
        rmp_serde::from_slice(&fixture.proof_bytes).unwrap();
    let mut vi: VerifierIndex<FULL_ROUNDS, Vesta, SRS<Vesta>> =
        rmp_serde::from_slice(&fixture.verifier_index_bytes).unwrap();

    let mut public_inputs = Vec::with_capacity(fixture.num_public_inputs);
    let mut cursor = &fixture.public_inputs_bytes[..];
    for _ in 0..fixture.num_public_inputs {
        public_inputs.push(Fp::deserialize_compressed(&mut cursor).unwrap());
    }

    // Reconstruct serde(skip) fields
    let srs = SRS::<Vesta>::create(vi.max_poly_size);
    srs.get_lagrange_basis(vi.domain);
    vi.srs = Arc::new(srs);
    vi.endo = endos::<mina_curves::pasta::Pallas>().0;
    let (linearization, powers_of_alpha) = expr_linearization(Some(&fixture.feature_flags), true);
    vi.linearization = linearization;
    vi.powers_of_alpha = powers_of_alpha;

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    verify_with_rng::<
        FULL_ROUNDS,
        Vesta,
        BaseSponge<VestaParameters>,
        ScalarSponge<Fp>,
        OpeningProof<Vesta, FULL_ROUNDS>,
        _,
    >(
        &group_map,
        &vi,
        &proof,
        &public_inputs,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
}

#[cfg(not(feature = "prover"))]
pub(super) fn load_and_verify_fixture_pallas(fixture_bytes: &[u8]) {
    let fixture: RawFixture = rmp_serde::from_slice(fixture_bytes).unwrap();
    let proof: ProverProof<Pallas, OpeningProof<Pallas, FULL_ROUNDS>, FULL_ROUNDS> =
        rmp_serde::from_slice(&fixture.proof_bytes).unwrap();
    let mut vi: VerifierIndex<FULL_ROUNDS, Pallas, SRS<Pallas>> =
        rmp_serde::from_slice(&fixture.verifier_index_bytes).unwrap();

    let mut public_inputs = Vec::with_capacity(fixture.num_public_inputs);
    let mut cursor = &fixture.public_inputs_bytes[..];
    for _ in 0..fixture.num_public_inputs {
        public_inputs.push(Fq::deserialize_compressed(&mut cursor).unwrap());
    }

    // Reconstruct serde(skip) fields
    let srs = SRS::<Pallas>::create(vi.max_poly_size);
    srs.get_lagrange_basis(vi.domain);
    vi.srs = Arc::new(srs);
    vi.endo = endos::<Vesta>().0;
    let (linearization, powers_of_alpha) = expr_linearization(Some(&fixture.feature_flags), true);
    vi.linearization = linearization;
    vi.powers_of_alpha = powers_of_alpha;

    let group_map = <Pallas as CommitmentCurve>::Map::setup();
    verify_with_rng::<
        FULL_ROUNDS,
        Pallas,
        BaseSponge<PallasParameters>,
        ScalarSponge<Fq>,
        OpeningProof<Pallas, FULL_ROUNDS>,
        _,
    >(
        &group_map,
        &vi,
        &proof,
        &public_inputs,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
}

#[test]
fn test_generic_gate() {
    #[cfg(feature = "prover")]
    {
        let gates = create_circuit(0, 0);

        // create witness
        let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
        fill_in_witness(0, &mut witness, &[]);

        TestFramework::<FULL_ROUNDS, Vesta>::default()
            .gates(gates)
            .witness(witness)
            .fixture_name("test_generic_gate")
            .setup()
            .prove_and_verify::<BaseSponge<VestaParameters>, ScalarSponge<Fp>>()
            .unwrap();
    }

    #[cfg(not(feature = "prover"))]
    load_and_verify_fixture(include_bytes!("fixtures/test_generic_gate.bin"));
}

#[cfg(feature = "prover")]
#[test]
fn test_generic_gate_pub() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::<FULL_ROUNDS, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify::<BaseSponge<VestaParameters>, ScalarSponge<Fp>>()
        .unwrap();
}

#[cfg(feature = "prover")]
#[test]
fn test_generic_gate_pub_all_zeros() {
    let public = vec![Fp::from(0u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::<FULL_ROUNDS, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify::<BaseSponge<VestaParameters>, ScalarSponge<Fp>>()
        .unwrap();
}

#[cfg(feature = "prover")]
#[test]
fn test_generic_gate_pub_empty() {
    let public = vec![];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    TestFramework::<FULL_ROUNDS, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup()
        .prove_and_verify::<BaseSponge<VestaParameters>, ScalarSponge<Fp>>()
        .unwrap();
}

#[cfg(all(feature = "bn254", feature = "prover"))]
#[test]
fn test_generic_gate_kzg() {
    let public = vec![Fr::from(3u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fr>; COLUMNS] = array::from_fn(|_| vec![Fr::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    // create and verify proof based on the witness
    <TestFramework<FULL_ROUNDS, _, KZGProof<Bn<ark_bn254::Config>>> as Default>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(public)
        .setup_with_custom_srs(|d1, srs_size| {
            let srs = PairingSRS::create(srs_size);
            srs.full_srs.get_lagrange_basis(d1);
            srs
        })
        .prove_and_verify::<BaseSponge<Bn254G1Config>, ScalarSponge<Fr>>()
        .unwrap();
}
