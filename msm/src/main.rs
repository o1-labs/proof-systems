use rand::{thread_rng, Rng};

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::columns::Column;
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

    let row_num = DOMAIN_SIZE;
    assert!(row_num <= DOMAIN_SIZE);

    for _row_i in 0..row_num {
        let a: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
        let b: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
        env.add_test_addition(a, b);
    }

    env
}

pub fn main() {
    // FIXME: use a proper RNG
    let mut rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    let env = generate_random_msm_witness();
    let witness = env.get_witness();
    let constraint_exprs = env.get_exprs_add();

    println!("Witness: {:?}", witness);
    println!("Constraints: {:?}", constraint_exprs);

    println!("Generating the proof");
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _>(
        domain,
        &srs,
        witness,
        constraint_exprs.clone(),
        &mut rng,
    );

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("=================\n   Proof verification result: {verifies}")
}
