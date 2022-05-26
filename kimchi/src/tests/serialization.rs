use crate::circuits::polynomials::generic::testing::{create_circuit, fill_in_witness};
use crate::circuits::polynomials::permutation::{zk_polynomial, zk_w3};
use crate::circuits::wires::COLUMNS;
use crate::proof::ProverProof;
use crate::prover_index::testing::new_index_for_test;
use crate::verifier::verify;
use crate::verifier_index::VerifierIndex;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::Zero;
use array_init::array_init;
use commitment_dlog::commitment::CommitmentCurve;
use commitment_dlog::srs::SRS;
use groupmap::GroupMap;
use mina_curves::pasta::fp::Fp;
use mina_curves::pasta::vesta::{Affine, VestaParameters};
use oracle::constants::PlonkSpongeConstantsKimchi;
use oracle::sponge::{DefaultFqSponge, DefaultFrSponge};
use std::sync::Arc;
use std::time::Instant;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[test]
pub fn test_serialization() {
    let public = vec![Fp::from(3u8); 5];
    let gates = create_circuit(0, public.len());

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
    fill_in_witness(0, &mut witness, &public);

    let index = new_index_for_test(gates, public.len());
    let verifier_index = index.verifier_index();

    let verifier_index_serialize =
        serde_json::to_string(&verifier_index).expect("couldn't serialize index");

    // verify the circuit satisfiability by the computed witness
    index.cs.verify(&witness, &public).unwrap();

    // add the proof to the batch
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &index).unwrap();

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
