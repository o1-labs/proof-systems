use ark_ff::{One, Zero};
use rand::thread_rng;

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::columns::Column;
use kimchi_msm::constraint::MSMCircuitEnv;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;
use kimchi_msm::{
    BN254G1Affine, BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254, DOMAIN_SIZE,
};

pub fn generate_random_msm_witness() -> MSMCircuitEnv<BN254G1Affine> {
    let mut circuit_env = MSMCircuitEnv::<BN254G1Affine>::empty();
    let mut _rng = thread_rng();

    let row_num = DOMAIN_SIZE;
    assert!(row_num <= DOMAIN_SIZE);

    let zero: Ff1 = Zero::zero();
    let one: Ff1 = One::one();
    let two: Ff1 = one + one;
    let three: Ff1 = one + two;
    // For now the verification only works if degree of each column as
    // a polynomial is zero (constant). Apparently.
    for row_i in 0..row_num {
        let (a, b) = match row_i % 3 {
            0 => (three, zero),
            1 => (one, one),
            2 => (two, one),
            //            3 => (one, three),
            _ => panic!("not possible"),
        };
        //let a: Ff1 = Ff1::rand(&mut rng);
        //let b: Ff1 = Ff1::rand(&mut rng);
        circuit_env.add_test_multiplication(a, b);
    }

    circuit_env
}

pub fn main() {
    // FIXME: use a proper RNG
    let mut rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    let circuit_env = generate_random_msm_witness();
    let witness = circuit_env.get_witness();
    let constraint_exprs = circuit_env.get_exprs_mul();

    println!("Witness: {:?}", witness);
    println!("Constraints: {:?}", constraint_exprs);

    println!("Generating the proof");
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _>(
        domain,
        &srs,
        constraint_exprs.clone(),
        witness,
        &mut rng,
    );

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(
        domain,
        &srs,
        constraint_exprs.clone(),
        &proof,
    );
    println!("=================\n   Proof verification result: {verifies}")
}
