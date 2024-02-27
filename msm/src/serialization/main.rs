use ark_ff::Zero;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::serialization::witness;
use kimchi_msm::witness::Witness;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::serialization::interpreter::InterpreterEnv;
use kimchi_msm::{Fp, BN254, DOMAIN_SIZE, LIMBS_NUM};

pub fn main() {
    // FIXME: use a proper RNG
    let mut _rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let _srs: PairingSRS<BN254> = get_bn254_srs(domain);

    const NUM_FIELD_ELEMENTS: usize = 1;
    let limbs = [Fp::zero(), Fp::zero(), Fp::zero()];
    let mut env = witness::Env::<NUM_FIELD_ELEMENTS, Fp>::create([limbs]);
    // Replace with ProofInputs from kimchi_msm::proof.rs
    let mut witness: Witness<DOMAIN_SIZE, Vec<Fp>> = Witness {
        cols: std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE)),
    };
    while env.step < NUM_FIELD_ELEMENTS {
        env.deserialize_field_element();
        for i in 0..3 {
            witness.cols[i].push(env.current_kimchi_limbs[i]);
        }
        for i in 0..LIMBS_NUM {
            witness.cols[3 + i].push(env.msm_limbs[i]);
        }
        for i in 0..19 {
            witness.cols[3 + LIMBS_NUM + i].push(env.intermediate_limbs[i]);
        }
        env.step += 1;
    }

    // println!("Generating the proof");
    // let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _>(
    //     domain,
    //     &srs,
    //     witness,
    //     constraints,
    //     &mut rng,
    // );

    // println!("Verifying the proof");
    // let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    // println!("Proof verification result: {verifies}")
}
