use kimchi::circuits::domains::EvaluationDomains;

use ark_ff::UniformRand;
use kimchi_msm::proof::Witness;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;
use kimchi_msm::BN254;
use kimchi_msm::DOMAIN_SIZE;
use kimchi_msm::{BaseSponge, Fp, OpeningProof, ScalarSponge};
use poly_commitment::pairing_proof::PairingSRS;

pub fn main() {
    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    // Trusted setup toxic waste
    let x = Fp::rand(&mut rand::rngs::OsRng);

    let mut srs: PairingSRS<BN254> = PairingSRS::create(x, DOMAIN_SIZE);
    srs.full_srs.add_lagrange_basis(domain.d1);

    let witness = Witness::random();

    println!("Generating the proof");
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, witness);

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("Proof verification result: {verifies}")
}
