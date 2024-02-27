use ark_ff::UniformRand;
use kimchi_msm::columns::Column;
use rand::thread_rng;

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::constraint::BuilderEnv;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;
use kimchi_msm::{
    BN254G1Affine, BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254, DOMAIN_SIZE,
};

pub fn generate_random_msm_witness() -> BuilderEnv<BN254G1Affine> {
    let mut env = BuilderEnv::<BN254G1Affine>::empty();
    let mut rng = thread_rng();

    let row_num = 5;
    assert!(row_num < DOMAIN_SIZE);

    for _row_i in 0..row_num {
        let a: Ff1 = Ff1::rand(&mut rng);
        let b: Ff1 = Ff1::rand(&mut rng);
        env.add_test_addition(a, b);
    }

    env
}

pub fn main() {
    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    let env = generate_random_msm_witness();
    let witness = env.get_witness();

    println!("Generating the proof");
    let constraints = vec![];
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column>(
        domain,
        &srs,
        witness,
        constraints,
    );

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("Proof verification result: {verifies}")
}
