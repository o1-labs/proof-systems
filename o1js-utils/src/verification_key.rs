use std::{
    fs::File,
    io::{BufReader, BufWriter},
    sync::Arc,
};

use base64::{engine::general_purpose, Engine as _};
use kimchi::{
    circuits::{
        constraints::FeatureFlags,
        lookup::lookups::{LookupFeatures, LookupPatterns},
        polynomials::permutation::{permutation_vanishing_polynomial, zk_w},
    },
    verifier_index::VerifierIndex,
};
use mina_curves::pasta::{Fp, Pallas, Vesta};
use once_cell::sync::OnceCell;
use poly_commitment::ipa::OpeningProof;
use rmp_serde::{Deserializer, Serializer};
use serde::{de::Error as SerdeDeError, Deserialize, Serialize};

fn compute_feature_flags(index: &VerifierIndex<Vesta, OpeningProof<Vesta>>) -> FeatureFlags {
    let xor = index.xor_comm.is_some();
    let range_check0 = index.range_check0_comm.is_some();
    let range_check1 = index.range_check1_comm.is_some();
    let foreign_field_add = index.foreign_field_add_comm.is_some();
    let foreign_field_mul = index.foreign_field_mul_comm.is_some();
    let rot = index.rot_comm.is_some();

    let lookup = index
        .lookup_index
        .as_ref()
        .map_or(false, |li| li.lookup_info.features.patterns.lookup);

    let runtime_tables = index
        .lookup_index
        .as_ref()
        .map_or(false, |li| li.runtime_tables_selector.is_some());

    let patterns = LookupPatterns {
        xor,
        lookup,
        range_check: range_check0 || range_check1 || rot,
        foreign_field_mul,
    };

    FeatureFlags {
        range_check0,
        range_check1,
        foreign_field_add,
        foreign_field_mul,
        xor,
        rot,
        lookup_features: LookupFeatures {
            patterns,
            joint_lookup_used: patterns.joint_lookups_used(),
            uses_runtime_tables: runtime_tables,
        },
    }
}

fn hydrate_vi(index: &mut VerifierIndex<Vesta, OpeningProof<Vesta>>) {
    let feature_flags = compute_feature_flags(index);
    let (linearization, alphas) =
        kimchi::linearization::expr_linearization::<Fp>(Some(&feature_flags), true);

    index.linearization = linearization;
    index.powers_of_alpha = alphas;

    index.permutation_vanishing_polynomial_m = OnceCell::new();
    index
        .permutation_vanishing_polynomial_m
        .set(permutation_vanishing_polynomial(
            index.domain,
            index.zk_rows,
        ))
        .unwrap();

    index.w = OnceCell::new();
    index.w.set(zk_w(index.domain, index.zk_rows)).unwrap();

    let (endo_q, _) = poly_commitment::ipa::endos::<Pallas>();
    index.endo = endo_q;
}

pub fn verification_key_from_o1js_base64(
    index: String,
    srs: Arc<poly_commitment::ipa::SRS<Vesta>>,
) -> Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> {
    let decoded_bytes = general_purpose::STANDARD
        .decode(index)
        .map_err(|err| err.to_string())
        .unwrap();
    let decoded_str = String::from_utf8(decoded_bytes).map_err(|e| json_error(e.to_string()))?;

    let vi: Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> =
        serde_json::from_str(&decoded_str);

    let mut verifier_index = match vi {
        Ok(vi) => vi,
        Err(e) => return Err(serde_json::Error::from(e)),
    };

    verifier_index.srs = srs;
    hydrate_vi(&mut verifier_index);
    Ok(verifier_index)
}

fn write_srs(
    path: &std::path::Path,
    srs: &poly_commitment::ipa::SRS<Vesta>,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer = BufWriter::new(File::create(path)?);
    srs.serialize(&mut Serializer::new(writer))?;
    Ok(())
}

fn read_srs(
    path: &std::path::Path,
) -> Result<Arc<poly_commitment::ipa::SRS<Vesta>>, Box<dyn std::error::Error>> {
    let reader = BufReader::new(File::open(path)?);
    let srs: poly_commitment::ipa::SRS<Vesta> =
        poly_commitment::ipa::SRS::deserialize(&mut Deserializer::new(reader))?;
    Ok(Arc::new(srs))
}

fn json_error(msg: impl Into<String>) -> serde_json::Error {
    <serde_json::Error as SerdeDeError>::custom(msg.into())
}

pub fn verification_key_from_o1js_json(
    index: String,
    srs: Arc<poly_commitment::ipa::SRS<Vesta>>,
) -> Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> {
    let vi: Result<VerifierIndex<Vesta, OpeningProof<Vesta>>, serde_json::Error> =
        serde_json::from_str(&index);

    let mut verifier_index = match vi {
        Ok(vi) => vi,
        Err(e) => return Err(serde_json::Error::from(e)),
    };

    println!("max_poly_size: {}", verifier_index.max_poly_size);
    verifier_index.srs = srs;
    hydrate_vi(&mut verifier_index);
    Ok(verifier_index)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mina_curves::pasta::Vesta;
    use poly_commitment::ipa::SRS;

    const VERIFICATION_KEY: &str = include_str!("./verification_key.vk");
    const VERIFICATION_KEY_BASE64: &str = include_str!("./verification_key.base64");

    const MAX_POLY_SIZE: usize = 65536;

    #[test]
    fn test_verifier_index_deserialize() {
        let srs = Arc::new(SRS::<Vesta>::create_parallel(MAX_POLY_SIZE));

        let vi = super::verification_key_from_o1js_json(VERIFICATION_KEY.to_string(), srs);
        assert!(vi.is_ok(), "Failed to deserialize verifier index from JSON");
    }

    #[test]
    fn test_verifier_index_deserialize_invalid() {
        let json = r#"{"invalid_key":"invalid_value"}"#;
        let srs = Arc::new(SRS::<Vesta>::create_parallel(MAX_POLY_SIZE));
        let vi = super::verification_key_from_o1js_json(json.to_string(), srs);
        assert!(
            vi.is_err(),
            "Expected error when deserializing invalid JSON"
        );
    }

    #[test]
    fn test_verification_key_from_o1js_base64() {
        let srs = Arc::new(SRS::<Vesta>::create_parallel(MAX_POLY_SIZE));
        let vi = super::verification_key_from_o1js_base64(VERIFICATION_KEY_BASE64.to_string(), srs);
        assert!(
            vi.is_ok(),
            "Failed to deserialize verifier index from base64"
        );
    }

    #[test]
    fn test_verification_key_from_o1js_base64_invalid() {
        let base64_str = "eyJkb21haW4iOiIwMDIwMDAwMDAwM==";
        let srs = Arc::new(SRS::<Vesta>::create_parallel(MAX_POLY_SIZE));
        let vi = super::verification_key_from_o1js_base64(base64_str.to_string(), srs);
        assert!(
            vi.is_err(),
            "Expected error when deserializing invalid base64"
        );
    }
}
