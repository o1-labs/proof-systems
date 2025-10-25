mod kimchi {
    use std::sync::Arc;

    use groupmap::GroupMap;
    use kimchi::{
        proof::ProverProof,
        verifier::{batch_verify, Context},
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

        verifier_index.srs = Arc::new(SRS::create(16 as usize));
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

        verifier_index.srs = Arc::new(SRS::create(16 as usize));
        Ok(verifier_index)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn test_verifier_index_deserialize() {
            let json = r#"{"domain":"00200000000000000d000000002000000000000000000000000000000000000000000000000000000000000001009878836750d0b3ae6c41c78645220000000000000000000000000000fe3fd2522dc9efa37580800e3dd3ab802afd3c53678894f1260666a0d0cbc202b403f551b4555a6d9adf0a7b05932c2d5d1a55aa151d8734ad4145de62eea05ca620010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000","max_poly_size":65536,"zk_rows":3,"public":1,"prev_challenges":0,"sigma_comm":[{"chunks":["931a589bc9a51b4bbd2162aa156c4ba15b536bc12f4b7a7a7311d5a96cdc331600"]},{"chunks":["1c90fc0734d22dfa6def797428ca41f671fe4b793c9d064c0168f05dc433c53b00"]},{"chunks":["a15c401fe9cde86ae2daa5b2e2ee30a320b6ca39c92bf9492d3219eb2398fd2400"]},{"chunks":["b05f4e724f7a0d80d387f7fc062b9d2d278fca72114bb2809edd79d119c7e91280"]},{"chunks":["6d43561d77acd27c23df7106fee13646f79d9daa5c0c80b582236c049d75510c80"]},{"chunks":["e31db40a7724332968bf23178c6867120c03304c2fddf04c611f858f169b811800"]},{"chunks":["f0eda702ac7c8224ad278573660af582a62ef552a8136a95a06f967001b9d81280"]}],"coefficients_comm":[{"chunks":["c1d564826665152d3636d1a69c983f9884ff1bf745e594ad11cc20f499ad2c0a00"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["2f0f5aa76c5e34b6e3bf0abb1badd14125e5d432c39b491f6ced7f9696db491580"]},{"chunks":["2f0f5aa76c5e34b6e3bf0abb1badd14125e5d432c39b491f6ced7f9696db491500"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["9650dc6b134aeadab5d94ac9822aeaf9ae66c917094db945941e11107b48a13480"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]},{"chunks":["000000000000000000000000000000000000000000000000000000000000000040"]}],"generic_comm":{"chunks":["20004ecb2d3c57ec9398658900ddc3a9d57515f2d3f64a2fa13517b87931fa3a80"]},"psm_comm":{"chunks":["012226265bceb2e5a8c78be27579a29c3636787563f2b4aa99c901633860200980"]},"complete_add_comm":{"chunks":["012226265bceb2e5a8c78be27579a29c3636787563f2b4aa99c901633860200980"]},"mul_comm":{"chunks":["012226265bceb2e5a8c78be27579a29c3636787563f2b4aa99c901633860200980"]},"emul_comm":{"chunks":["012226265bceb2e5a8c78be27579a29c3636787563f2b4aa99c901633860200980"]},"endomul_scalar_comm":{"chunks":["012226265bceb2e5a8c78be27579a29c3636787563f2b4aa99c901633860200980"]},"range_check0_comm":{"chunks":["7b62fad92d3e1290a32ed348d8a78ce95f7faf5e9ca7e831a124389ba80d562900"]},"range_check1_comm":null,"foreign_field_add_comm":null,"foreign_field_mul_comm":null,"xor_comm":null,"rot_comm":null,"shift":["0100000000000000000000000000000000000000000000000000000000000000","e3a214e91334d0caf1eb85df5bd7524d73d5eb7aaf742a7eb2d40bfdc8cdb900","5a696526fa309c412c10e86604c3c0ad2cd9443dd85b823203721281cfbf3300","11848e2c0bf18b0e9f7c8c34db4621b6c75afaa1e32d0f96164e9529bbf48700","9358be9d3ef26bb05bbaaba8c3262e0bb65d36479694d15ef16c9f3b3771ec00","106d491c728c240cf04564b85c586b4072a1f1641fd3684c08554ccc9791f300","a3ee5991230c1903d2dfc543013c3567e0839a29a4e6d212eedb999703ddb800"],"lookup_index":{"joint_lookup_used":false,"lookup_table":[{"chunks":["f1c80eb461739b432283d94deb00da2c2fa336c6c2fe157ed29e77311d104e3980"]}],"lookup_selectors":{"xor":null,"lookup":null,"range_check":{"chunks":["7b62fad92d3e1290a32ed348d8a78ce95f7faf5e9ca7e831a124389ba80d562900"]},"ffmul":null},"table_ids":{"chunks":["6262fb6b1543fbdf715ddecada229ceb817c89f7534894ba803cbbaf901f671a00"]},"lookup_info":{"max_per_row":4,"max_joint_size":1,"features":{"patterns":{"xor":false,"lookup":false,"range_check":true,"foreign_field_mul":false},"joint_lookup_used":false,"uses_runtime_tables":false}},"runtime_tables_selector":null}}"#;
            let vi = super::verification_key_from_o1js_json(json.to_string());
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
            let base64_str = "eyJkb21haW4iOiIwMDIwMDAwMDAwMDAwMDAwMGQwMDAwMDAwMDIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDEwMDk4Nzg4MzY3NTBkMGIzYWU2YzQxYzc4NjQ1MjIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwZmUzZmQyNTIyZGM5ZWZhMzc1ODA4MDBlM2RkM2FiODAyYWZkM2M1MzY3ODg5NGYxMjYwNjY2YTBkMGNiYzIwMmI0MDNmNTUxYjQ1NTVhNmQ5YWRmMGE3YjA1OTMyYzJkNWQxYTU1YWExNTFkODczNGFkNDE0NWRlNjJlZWEwNWNhNjIwMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWF4X3BvbHlfc2l6ZSI6NjU1MzYsInprX3Jvd3MiOjMsInB1YmxpYyI6MSwicHJldl9jaGFsbGVuZ2VzIjowLCJzaWdtYV9jb21tIjpbeyJjaHVua3MiOlsiOTMxYTU4OWJjOWE1MWI0YmJkMjE2MmFhMTU2YzRiYTE1YjUzNmJjMTJmNGI3YTdhNzMxMWQ1YTk2Y2RjMzMxNjAwIl19LHsiY2h1bmtzIjpbIjFjOTBmYzA3MzRkMjJkZmE2ZGVmNzk3NDI4Y2E0MWY2NzFmZTRiNzkzYzlkMDY0YzAxNjhmMDVkYzQzM2M1M2IwMCJdfSx7ImNodW5rcyI6WyJhMTVjNDAxZmU5Y2RlODZhZTJkYWE1YjJlMmVlMzBhMzIwYjZjYTM5YzkyYmY5NDkyZDMyMTllYjIzOThmZDI0MDAiXX0seyJjaHVua3MiOlsiYjA1ZjRlNzI0ZjdhMGQ4MGQzODdmN2ZjMDYyYjlkMmQyNzhmY2E3MjExNGJiMjgwOWVkZDc5ZDExOWM3ZTkxMjgwIl19LHsiY2h1bmtzIjpbIjZkNDM1NjFkNzdhY2QyN2MyM2RmNzEwNmZlZTEzNjQ2Zjc5ZDlkYWE1YzBjODBiNTgyMjM2YzA0OWQ3NTUxMGM4MCJdfSx7ImNodW5rcyI6WyJlMzFkYjQwYTc3MjQzMzI5NjhiZjIzMTc4YzY4NjcxMjBjMDMzMDRjMmZkZGYwNGM2MTFmODU4ZjE2OWI4MTE4MDAiXX0seyJjaHVua3MiOlsiZjBlZGE3MDJhYzdjODIyNGFkMjc4NTczNjYwYWY1ODJhNjJlZjU1MmE4MTM2YTk1YTA2Zjk2NzAwMWI5ZDgxMjgwIl19XSwiY29lZmZpY2llbnRzX2NvbW0iOlt7ImNodW5rcyI6WyJjMWQ1NjQ4MjY2NjUxNTJkMzYzNmQxYTY5Yzk4M2Y5ODg0ZmYxYmY3NDVlNTk0YWQxMWNjMjBmNDk5YWQyYzBhMDAiXX0seyJjaHVua3MiOlsiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQwIl19LHsiY2h1bmtzIjpbIjJmMGY1YWE3NmM1ZTM0YjZlM2JmMGFiYjFiYWRkMTQxMjVlNWQ0MzJjMzliNDkxZjZjZWQ3Zjk2OTZkYjQ5MTU4MCJdfSx7ImNodW5rcyI6WyIyZjBmNWFhNzZjNWUzNGI2ZTNiZjBhYmIxYmFkZDE0MTI1ZTVkNDMyYzM5YjQ5MWY2Y2VkN2Y5Njk2ZGI0OTE1MDAiXX0seyJjaHVua3MiOlsiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQwIl19LHsiY2h1bmtzIjpbIjk2NTBkYzZiMTM0YWVhZGFiNWQ5NGFjOTgyMmFlYWY5YWU2NmM5MTcwOTRkYjk0NTk0MWUxMTEwN2I0OGExMzQ4MCJdfSx7ImNodW5rcyI6WyIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNDAiXX0seyJjaHVua3MiOlsiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQwIl19LHsiY2h1bmtzIjpbIjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA0MCJdfSx7ImNodW5rcyI6WyIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNDAiXX0seyJjaHVua3MiOlsiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQwIl19LHsiY2h1bmtzIjpbIjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA0MCJdfSx7ImNodW5rcyI6WyIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNDAiXX0seyJjaHVua3MiOlsiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQwIl19LHsiY2h1bmtzIjpbIjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA0MCJdfV0sImdlbmVyaWNfY29tbSI6eyJjaHVua3MiOlsiMjAwMDRlY2IyZDNjNTdlYzkzOTg2NTg5MDBkZGMzYTlkNTc1MTVmMmQzZjY0YTJmYTEzNTE3Yjg3OTMxZmEzYTgwIl19LCJwc21fY29tbSI6eyJjaHVua3MiOlsiMDEyMjI2MjY1YmNlYjJlNWE4Yzc4YmUyNzU3OWEyOWMzNjM2Nzg3NTYzZjJiNGFhOTljOTAxNjMzODYwMjAwOTgwIl19LCJjb21wbGV0ZV9hZGRfY29tbSI6eyJjaHVua3MiOlsiMDEyMjI2MjY1YmNlYjJlNWE4Yzc4YmUyNzU3OWEyOWMzNjM2Nzg3NTYzZjJiNGFhOTljOTAxNjMzODYwMjAwOTgwIl19LCJtdWxfY29tbSI6eyJjaHVua3MiOlsiMDEyMjI2MjY1YmNlYjJlNWE4Yzc4YmUyNzU3OWEyOWMzNjM2Nzg3NTYzZjJiNGFhOTljOTAxNjMzODYwMjAwOTgwIl19LCJlbXVsX2NvbW0iOnsiY2h1bmtzIjpbIjAxMjIyNjI2NWJjZWIyZTVhOGM3OGJlMjc1NzlhMjljMzYzNjc4NzU2M2YyYjRhYTk5YzkwMTYzMzg2MDIwMDk4MCJdfSwiZW5kb211bF9zY2FsYXJfY29tbSI6eyJjaHVua3MiOlsiMDEyMjI2MjY1YmNlYjJlNWE4Yzc4YmUyNzU3OWEyOWMzNjM2Nzg3NTYzZjJiNGFhOTljOTAxNjMzODYwMjAwOTgwIl19LCJyYW5nZV9jaGVjazBfY29tbSI6eyJjaHVua3MiOlsiN2I2MmZhZDkyZDNlMTI5MGEzMmVkMzQ4ZDhhNzhjZTk1ZjdmYWY1ZTljYTdlODMxYTEyNDM4OWJhODBkNTYyOTAwIl19LCJyYW5nZV9jaGVjazFfY29tbSI6bnVsbCwiZm9yZWlnbl9maWVsZF9hZGRfY29tbSI6bnVsbCwiZm9yZWlnbl9maWVsZF9tdWxfY29tbSI6bnVsbCwieG9yX2NvbW0iOm51bGwsInJvdF9jb21tIjpudWxsLCJzaGlmdCI6WyIwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiZTNhMjE0ZTkxMzM0ZDBjYWYxZWI4NWRmNWJkNzUyNGQ3M2Q1ZWI3YWFmNzQyYTdlYjJkNDBiZmRjOGNkYjkwMCIsIjVhNjk2NTI2ZmEzMDljNDEyYzEwZTg2NjA0YzNjMGFkMmNkOTQ0M2RkODViODIzMjAzNzIxMjgxY2ZiZjMzMDAiLCIxMTg0OGUyYzBiZjE4YjBlOWY3YzhjMzRkYjQ2MjFiNmM3NWFmYWExZTMyZDBmOTYxNjRlOTUyOWJiZjQ4NzAwIiwiOTM1OGJlOWQzZWYyNmJiMDViYmFhYmE4YzMyNjJlMGJiNjVkMzY0Nzk2OTRkMTVlZjE2YzlmM2IzNzcxZWMwMCIsIjEwNmQ0OTFjNzI4YzI0MGNmMDQ1NjRiODVjNTg2YjQwNzJhMWYxNjQxZmQzNjg0YzA4NTU0Y2NjOTc5MWYzMDAiLCJhM2VlNTk5MTIzMGMxOTAzZDJkZmM1NDMwMTNjMzU2N2UwODM5YTI5YTRlNmQyMTJlZWRiOTk5NzAzZGRiODAwIl0sImxvb2t1cF9pbmRleCI6eyJqb2ludF9sb29rdXBfdXNlZCI6ZmFsc2UsImxvb2t1cF90YWJsZSI6W3siY2h1bmtzIjpbImYxYzgwZWI0NjE3MzliNDMyMjgzZDk0ZGViMDBkYTJjMmZhMzM2YzZjMmZlMTU3ZWQyOWU3NzMxMWQxMDRlMzk4MCJdfV0sImxvb2t1cF9zZWxlY3RvcnMiOnsieG9yIjpudWxsLCJsb29rdXAiOm51bGwsInJhbmdlX2NoZWNrIjp7ImNodW5rcyI6WyI3YjYyZmFkOTJkM2UxMjkwYTMyZWQzNDhkOGE3OGNlOTVmN2ZhZjVlOWNhN2U4MzFhMTI0Mzg5YmE4MGQ1NjI5MDAiXX0sImZmbXVsIjpudWxsfSwidGFibGVfaWRzIjp7ImNodW5rcyI6WyI2MjYyZmI2YjE1NDNmYmRmNzE1ZGRlY2FkYTIyOWNlYjgxN2M4OWY3NTM0ODk0YmE4MDNjYmJhZjkwMWY2NzFhMDAiXX0sImxvb2t1cF9pbmZvIjp7Im1heF9wZXJfcm93Ijo0LCJtYXhfam9pbnRfc2l6ZSI6MSwiZmVhdHVyZXMiOnsicGF0dGVybnMiOnsieG9yIjpmYWxzZSwibG9va3VwIjpmYWxzZSwicmFuZ2VfY2hlY2siOnRydWUsImZvcmVpZ25fZmllbGRfbXVsIjpmYWxzZX0sImpvaW50X2xvb2t1cF91c2VkIjpmYWxzZSwidXNlc19ydW50aW1lX3RhYmxlcyI6ZmFsc2V9fSwicnVudGltZV90YWJsZXNfc2VsZWN0b3IiOm51bGx9fQ==";
            let vi = super::verification_key_from_o1js_base64(base64_str.to_string());
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
            let proof_base64 = r#"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"#;
            let proof = super::deserialize(proof_base64);
            assert!(proof.is_ok(), "Failed to deserialize proof from base64");
        }
    }
}
