use rand::Rng;

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::columns::Column;
use kimchi_msm::ffa::{
    columns::FFA_N_COLUMNS,
    constraint::ConstraintBuilderEnv as FFAConstraintBuilderEnv,
    interpreter::{self as ffa_interpreter, FFAInterpreterEnv},
    witness::WitnessBuilderEnv as FFAWitnessBuilderEnv,
};
use kimchi_msm::lookups::LookupTableIDs;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;
use kimchi_msm::{BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254, DOMAIN_SIZE};

pub fn main() {
    // FIXME: use a proper RNG
    let mut rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain_size = DOMAIN_SIZE;
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    let mut witness_env = FFAWitnessBuilderEnv::<Fp>::empty();
    let mut constraint_env = FFAConstraintBuilderEnv::<Fp>::empty();

    ffa_interpreter::constrain_multiplication(&mut constraint_env);

    let row_num = 10;
    assert!(row_num <= DOMAIN_SIZE);

    for _row_i in 0..row_num {
        let a: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
        let b: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
        ffa_interpreter::test_multiplication(&mut witness_env, a, b);
        witness_env.next_row();
    }

    let inputs = witness_env.get_witness(domain);
    let constraints = constraint_env.constraints;

    println!("Generating the proof");
    let proof = prove::<
        _,
        OpeningProof,
        BaseSponge,
        ScalarSponge,
        Column,
        _,
        FFA_N_COLUMNS,
        LookupTableIDs,
    >(domain, &srs, &constraints, inputs, &mut rng)
    .unwrap();

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, FFA_N_COLUMNS>(
        domain,
        &srs,
        &constraints,
        &proof,
    );
    println!("Proof verification result: {verifies}")
}
