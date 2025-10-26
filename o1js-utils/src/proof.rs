use ark_ff::{BigInt, PrimeField};
use base64::{engine::general_purpose, Engine as _};
use groupmap::GroupMap;
use kimchi::{proof::ProverProof, verifier::verify, verifier_index::VerifierIndex};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct JsonProof {
    proof: String,
    #[serde(rename = "publicInputFields")]
    public_inputs: Vec<String>,
}

struct O1jsProof {
    proof: ProverProof<Vesta, OpeningProof<Vesta>>,
    public_inputs: Vec<Fp>,
}

pub fn json_proof_to_o1js_proof(json_proof: JsonProof) -> Result<O1jsProof, String> {
    let proof = base64_to_proof(&json_proof.proof)?;

    let mut public_inputs = Vec::with_capacity(json_proof.public_inputs.len());
    for input_str in json_proof.public_inputs {
        let x = BigInt::from_str(&input_str).unwrap();
        let input_fp = Fp::from_bigint(x).unwrap();
        public_inputs.push(input_fp);
    }

    Ok(O1jsProof {
        proof,
        public_inputs,
    })
}

pub fn parse_json_proof(json_proof: &str) -> Result<JsonProof, serde_json::Error> {
    serde_json::from_str::<JsonProof>(json_proof)
}

pub fn base64_to_proof(
    proof_base64: &str,
) -> Result<ProverProof<Vesta, OpeningProof<Vesta>>, String> {
    let bytes = general_purpose::STANDARD
        .decode(proof_base64)
        .map_err(|err| err.to_string())?;
    rmp_serde::from_slice::<ProverProof<Vesta, OpeningProof<Vesta>>>(&bytes)
        .map_err(|err| format!("failed to decode prover proof: {err:?}"))
}

pub fn verify_proof(
    verifier_index: &VerifierIndex<Vesta, OpeningProof<Vesta>>,
    proof: &ProverProof<Vesta, OpeningProof<Vesta>>,
    public_input: &[Fp],
) -> bool {
    let group_map = <Vesta as CommitmentCurve>::Map::setup();

    match verify::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
        OpeningProof<Vesta>,
    >(&group_map, verifier_index, proof, public_input)
    {
        Ok(()) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use poly_commitment::ipa::SRS;

    use crate::verification_key::verification_key_from_o1js_base64;

    use super::*;

    const PROOF_BASE64: &str = include_str!("./proof.base64");
    const PROOF_JSON: &str = include_str!("./proof.json");

    const MAX_POLY_SIZE: usize = 65536;

    const VERIFICATION_KEY_BASE64: &str = include_str!("./verification_key.base64");

    #[test]
    fn deserialize_proof_test() {
        let proof = base64_to_proof(PROOF_BASE64);
        assert!(proof.is_ok(), "Failed to deserialize proof from base64");
    }

    #[test]
    fn verify_base64_proof_e2e() {
        println!("Proof deserialized start");

        let proof = base64_to_proof(PROOF_BASE64).expect("Failed to deserialize proof");
        println!("Proof deserialized successfully");

        let srs = Arc::new(SRS::<Vesta>::create_parallel(MAX_POLY_SIZE));
        let verifier_index =
            verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string(), srs)
                .expect("Failed to deserialize verifier index from base64");
        println!("Proof deserialized successfully 111");

        let public_input: Vec<super::Fp> = vec![Fp::from(8)];

        let is_valid = super::verify_proof(&verifier_index, &proof, &public_input);
        assert!(is_valid, "Proof verification failed");
    }

    #[test]
    fn verify_base64_proof_e2e_invalid() {
        let proof = base64_to_proof(PROOF_BASE64).expect("Failed to deserialize proof");
        let srs = Arc::new(poly_commitment::ipa::SRS::<Vesta>::create_parallel(
            MAX_POLY_SIZE,
        ));
        let verifier_index =
            verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string(), srs)
                .expect("Failed to deserialize verifier index from base64");

        let public_input = [Fp::from(8)];
        let is_valid = verify_proof(&verifier_index, &proof, &public_input);
        assert!(is_valid, "Proof verification failed");
    }

    #[test]
    pub fn verify_o1jsjson_proof_e2e() {
        let json_proof =
            parse_json_proof(PROOF_JSON).expect("Failed to parse proof from JSON string");
        let o1js_proof =
            json_proof_to_o1js_proof(json_proof).expect("Failed to convert JSON proof to O1js");

        let srs = Arc::new(poly_commitment::ipa::SRS::<Vesta>::create_parallel(
            MAX_POLY_SIZE,
        ));
        let verifier_index =
            verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string(), srs)
                .expect("Failed to deserialize verifier index from base64");

        let is_valid = verify_proof(
            &verifier_index,
            &o1js_proof.proof,
            &o1js_proof.public_inputs,
        );
        assert!(is_valid, "Proof verification failed");
    }
}
