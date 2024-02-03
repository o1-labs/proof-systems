use kimchi::circuits::domains::EvaluationDomains;

use kimchi_msm::precomputed_srs::{get_bn254_srs, test_serialization};
use kimchi_msm::proof::Witness;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;
use kimchi_msm::DOMAIN_SIZE;
use kimchi_msm::{BaseSponge, Fp, OpeningProof, ScalarSponge};

pub fn main() {
    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs = get_bn254_srs(domain);

    // The f_{i}(X), provided by the prover
    let lookups = vec![];

    // Provided by the prover, it is m(X)
    let lookup_counters = vec![];

    // TODO: Use random witness atm.
    let witness = Witness::random();

    println!("Generating the proof");
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge>(
        domain,
        &srs,
        lookups,
        lookup_counters,
        witness,
    );
    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("Proof verification result: {verifies}")
}
