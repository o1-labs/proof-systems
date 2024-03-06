use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::lookups::LookupTableIDs;
use kimchi_msm::serialization::{witness, N_INTERMEDIATE_LIMBS};
use kimchi_msm::witness::Witness;
use poly_commitment::pairing_proof::PairingSRS;

use kimchi_msm::columns::Column;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::proof::ProofInputs;
use kimchi_msm::prover::prove;
use kimchi_msm::serialization::constraints;
use kimchi_msm::serialization::interpreter::deserialize_field_element;
use kimchi_msm::verifier::verify;
use kimchi_msm::{BaseSponge, Fp, OpeningProof, ScalarSponge, BN254, DOMAIN_SIZE, N_LIMBS};
use rand::Rng as _;

const SERIALIZATION_N_COLUMNS: usize = 3 + N_INTERMEDIATE_LIMBS + N_LIMBS;

pub fn main() {
    // FIXME: use a proper RNG
    let mut rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    let mut witness_env = witness::Env::<Fp>::create();
    let mut constraint_env = constraints::Env::<Fp>::create();
    let mut witness: Witness<SERIALIZATION_N_COLUMNS, Vec<Fp>> = Witness {
        cols: std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE)),
    };

    // FIXME: this could be read from a file or a CLI argument
    let field_elements = [[
        rng.gen_range(0..1000),
        rng.gen_range(0..1000),
        rng.gen_range(0..1000),
    ]];

    let mut constraints = vec![];
    for limbs in field_elements {
        // Witness
        deserialize_field_element(&mut witness_env, limbs);
        for i in 0..3 {
            witness.cols[i].push(witness_env.current_kimchi_limbs[i]);
        }
        for i in 0..N_LIMBS {
            witness.cols[3 + i].push(witness_env.msm_limbs[i]);
        }
        for i in 0..N_INTERMEDIATE_LIMBS {
            witness.cols[3 + N_LIMBS + i].push(witness_env.intermediate_limbs[i]);
        }

        // Constraints
        deserialize_field_element(&mut constraint_env, limbs);
        // FIXME: do not use clone.
        // FIXME: this is ugly, but only to make it work for now.
        // It does suppose the same constraint aalways have the same index.
        // Totally wrong assumption according to the current env implementation.
        for (idx, cst) in constraint_env.constraints.iter() {
            if *idx >= constraints.len() {
                constraints.push(cst.clone())
            }
        }
    }

    let proof_inputs = ProofInputs {
        evaluations: witness,
        mvlookups: vec![],
    };

    println!("Number of constraints: {}", constraints.len());

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
    >(domain, &srs, &constraints, proof_inputs, &mut rng)
    .unwrap();

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, SERIALIZATION_N_COLUMNS>(
        domain,
        &srs,
        &constraints,
        &proof,
    );
    println!("Proof verification result: {verifies}")
}
