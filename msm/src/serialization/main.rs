use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::lookups::LookupTableIDs;
use kimchi_msm::serialization::{witness, N_INTERMEDIATE_LIMBS};
use kimchi_msm::witness::Witness;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::columns::Column;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::proof::ProofInputs;
use kimchi_msm::prover::prove;
use kimchi_msm::serialization::witness::deserialize_field_element;
use kimchi_msm::verifier::verify;
use kimchi_msm::{BaseSponge, Fp, OpeningProof, ScalarSponge, BN254, DOMAIN_SIZE, LIMBS_NUM};

const SERIALIZATION_N_COLUMNS: usize = 3 + N_INTERMEDIATE_LIMBS + LIMBS_NUM;

pub fn main() {
    // FIXME: use a proper RNG
    let mut rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    let mut env = witness::Env::<Fp>::create();
    let mut witness: Witness<SERIALIZATION_N_COLUMNS, Vec<Fp>> = Witness {
        cols: std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE)),
    };

    // FIXME: this could be read from a file or a CLI argument
    let field_elements = [[0, 0, 0]];
    for limbs in field_elements {
        deserialize_field_element(&mut env, limbs);
        for i in 0..3 {
            witness.cols[i].push(env.current_kimchi_limbs[i]);
        }
        for i in 0..LIMBS_NUM {
            witness.cols[3 + i].push(env.msm_limbs[i]);
        }
        for i in 0..N_INTERMEDIATE_LIMBS {
            witness.cols[3 + LIMBS_NUM + i].push(env.intermediate_limbs[i]);
        }
    }

    let _constraints = vec![];
    let proof_inputs = ProofInputs {
        evaluations: witness,
        mvlookups: vec![],
    };

    println!("Generating the proof");
    let proof = prove::<
        _,
        OpeningProof,
        BaseSponge,
        ScalarSponge,
        Column,
        _,
        SERIALIZATION_N_COLUMNS,
        LookupTableIDs,
    >(domain, &srs, proof_inputs, _constraints, &mut rng);

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, SERIALIZATION_N_COLUMNS>(
        domain, &srs, &proof,
    );
    println!("Proof verification result: {verifies}")
}
