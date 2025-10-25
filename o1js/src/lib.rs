mod kimchi {
    use std::sync::Arc;

    use groupmap::GroupMap;
    use kimchi::{
        proof::ProverProof,
        verifier::{batch_verify, verify, Context},
        verifier_index::VerifierIndex,
    };
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof, SRS};
    use serde::de::Error as SerdeDeError;

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

    pub fn verification_key_from_o1js_base64(
        index: String,
    ) -> Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> {
        let decoded_bytes = base64::decode(index).map_err(|e| json_error(e.to_string()))?;
        let decoded_str =
            String::from_utf8(decoded_bytes).map_err(|e| json_error(e.to_string()))?;

        let vi: Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> =
            serde_json::from_str(&decoded_str);

        let mut verifier_index = match vi {
            Ok(vi) => vi,
            Err(e) => return Err(serde_json::Error::from(e)),
        };

        verifier_index.srs = Arc::new(SRS::create(verifier_index.max_poly_size));
        Ok(verifier_index)
    }

    pub fn deserialize(
        proof_base64: &str,
    ) -> Result<ProverProof<Vesta, OpeningProof<Vesta>>, String> {
        let bytes = base64::decode(proof_base64).map_err(|err| err.to_string())?;
        rmp_serde::from_slice::<ProverProof<Vesta, OpeningProof<Vesta>>>(&bytes)
            .map_err(|err| format!("failed to decode prover proof: {err:?}"))
    }

    fn json_error(msg: impl Into<String>) -> serde_json::Error {
        <serde_json::Error as SerdeDeError>::custom(msg.into())
    }

    pub fn verify_o1js_kimchi_proof(
        verifier_index: &VerifierIndex<Vesta, OpeningProof<Vesta>>,
        proof: &ProverProof<Vesta, OpeningProof<Vesta>>,
        public_input: &[Fp],
    ) -> bool {
        let group_map = <Vesta as CommitmentCurve>::Map::setup();

        let context = Context {
            verifier_index,
            proof,
            public_input,
        };

        match batch_verify::<
            Vesta,
            DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
            DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
            OpeningProof<Vesta>,
        >(&group_map, &[context])
        {
            Ok(()) => true,
            Err(_) => false,
        }
    }
    pub fn verification_key_from_o1js_json(
        index: String,
    ) -> Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> {
        let vi: Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> =
            serde_json::from_str(&index);

        let mut verifier_index = match vi {
            Ok(vi) => vi,
            Err(e) => return Err(serde_json::Error::from(e)),
        };

        verifier_index.srs = Arc::new(SRS::create(verifier_index.max_poly_size));
        Ok(verifier_index)
    }

    #[cfg(test)]
    mod tests {
        use ark_ff::Fp;

        const VERIFICATION_KEY: &str = include_str!("./verification_key.vk");
        const VERIFICATION_KEY_BASE64: &str = include_str!("./verification_key.base64");
        const PROOF_BASE64: &str = include_str!("./proof.base64");

        #[test]
        fn test_verifier_index_deserialize() {
            let vi = super::verification_key_from_o1js_json(VERIFICATION_KEY.to_string());
            assert!(vi.is_ok(), "Failed to deserialize verifier index from JSON");
        }

        #[test]
        fn test_verifier_index_deserialize_invalid() {
            let json = r#"{"invalid_key":"invalid_value"}"#;
            let vi = super::verification_key_from_o1js_json(json.to_string());
            assert!(
                vi.is_err(),
                "Expected error when deserializing invalid JSON"
            );
        }

        #[test]
        fn test_verification_key_from_o1js_base64() {
            let vi = super::verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string());
            assert!(
                vi.is_ok(),
                "Failed to deserialize verifier index from base64"
            );
        }

        #[test]
        fn test_verification_key_from_o1js_base64_invalid() {
            let base64_str = "eyJkb21haW4iOiIwMDIwMDAwMDAwM==";
            let vi = super::verification_key_from_o1js_base64(base64_str.to_string());
            assert!(
                vi.is_err(),
                "Expected error when deserializing invalid base64"
            );
        }

        #[test]
        fn deserialize_proof_test() {
            let proof = super::deserialize(PROOF_BASE64);
            assert!(proof.is_ok(), "Failed to deserialize proof from base64");
        }

        #[test]
        fn verify_proof_e2e() {
            println!("Proof deserialized start");

            let proof = super::deserialize(PROOF_BASE64).expect("Failed to deserialize proof");
            println!("Proof deserialized successfully");
            let verifier_index =
                super::verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string())
                    .expect("Failed to deserialize verifier index from base64");
            println!("Proof deserialized successfully 111");

            let public_input: Vec<super::Fp> = vec![Fp::from(8)];

            let is_valid = super::verify_proof(&verifier_index, &proof, &public_input);
            assert!(is_valid, "Proof verification failed");
        }

        #[test]
        fn verify_proof_e2e_invalid() {
            let proof = super::deserialize(PROOF_BASE64).expect("Failed to deserialize proof");
            let verifier_index =
                super::verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string())
                    .expect("Failed to deserialize verifier index from base64");

            let public_input = [Fp::from(8)];
            let is_valid = super::verify_proof(&verifier_index, &proof, &public_input);
            assert!(is_valid, "Proof verification failed");
        }
    }
}
