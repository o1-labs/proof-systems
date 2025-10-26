use std::sync::Arc;

use mina_curves::pasta::Vesta;

pub mod proof;
pub mod verification_key;

#[test]
fn demo_uses_file() {
    let proof_data: &str = include_str!("../../../../../../../../zkfunction-proof.json");
    let vk_data: &str = include_str!("../../../../../../../../zkfunction-verification-key.data");

    // parse proof

    let json_proof =
        proof::parse_json_proof(&proof_data).expect("Failed to parse proof from JSON string");
    let o1js_proof =
        proof::json_proof_to_o1js_proof(json_proof).expect("Failed to convert JSON proof to O1js");

    // vk

    let srs = Arc::new(poly_commitment::ipa::SRS::<Vesta>::create_parallel(65536));
    let verifier_index =
        verification_key::verification_key_from_o1js_base64(vk_data.to_string(), srs)
            .expect("Failed to deserialize verifier index from base64");

    let is_valid = proof::verify_proof(
        &verifier_index,
        &o1js_proof.proof,
        &o1js_proof.public_inputs,
    );
    assert!(is_valid, "Proof verification failed");
}
