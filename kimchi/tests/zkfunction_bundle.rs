use std::{env, fs, path::PathBuf, sync::{Arc, OnceLock}};

use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use groupmap::GroupMap;
use kimchi::{
    circuits::{
        constraints::FeatureFlags,
        lookup::lookups::{LookupFeatures, LookupPatterns},
        polynomials::permutation::{permutation_vanishing_polynomial, zk_w},
    },
    linearization::expr_linearization,
    proof::ProverProof,
    verifier::verify_with_rng,
    verifier_index::VerifierIndex,
};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::{
    commitment::CommitmentCurve,
    ipa::{OpeningProof, SRS},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde::Deserialize;

type PastaFpSrs = SRS<Vesta>;
type PastaFpVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, PastaFpSrs>;
type PastaFpProof = ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS>;
type PastaFpBaseSponge =
    DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
type PastaFpScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KimchiJsonProof {
    public_input_fields: Vec<String>,
    proof: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZkFunctionKimchiBundle {
    circuit: String,
    proof: KimchiJsonProof,
    verification_key: String,
    srs: Vec<OrInfinityJson>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OrInfinityJson {
    Infinity(String),
    Finite { x: String, y: String },
}

#[test]
#[ignore = "requires ZKFUNCTION_KIMCHI_BUNDLE=/absolute/path/to/bundle.json"]
fn verifies_zkfunction_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = env::var_os("ZKFUNCTION_KIMCHI_BUNDLE")
        .map(PathBuf::from)
        .ok_or("missing ZKFUNCTION_KIMCHI_BUNDLE")?;

    let bundle: ZkFunctionKimchiBundle = serde_json::from_slice(&fs::read(bundle_path)?)?;

    let proof_bytes = STANDARD.decode(bundle.proof.proof)?;
    let verification_key_json = String::from_utf8(STANDARD.decode(bundle.verification_key)?)?;

    let proof: PastaFpProof = rmp_serde::from_slice(&proof_bytes)?;
    let srs = srs_from_json_points(&bundle.srs)?;
    let verifier_index: PastaFpVerifierIndex = serde_json::from_str(&verification_key_json)?;
    let verifier_index = hydrate_verifier_index(verifier_index, Arc::new(srs));
    let public_input = parse_public_input(&bundle.proof.public_input_fields)?;

    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    verify_with_rng::<
        FULL_ROUNDS,
        Vesta,
        PastaFpBaseSponge,
        PastaFpScalarSponge,
        OpeningProof<Vesta, FULL_ROUNDS>,
        ChaCha20Rng,
    >(&group_map, &verifier_index, &proof, &public_input, &mut rng)?;

    println!("verified {}", bundle.circuit);
    Ok(())
}

fn compute_feature_flags(index: &PastaFpVerifierIndex) -> FeatureFlags {
    let xor = index.xor_comm.is_some();
    let range_check0 = index.range_check0_comm.is_some();
    let range_check1 = index.range_check1_comm.is_some();
    let foreign_field_add = index.foreign_field_add_comm.is_some();
    let foreign_field_mul = index.foreign_field_mul_comm.is_some();
    let rot = index.rot_comm.is_some();

    let lookup = index
        .lookup_index
        .as_ref()
        .is_some_and(|lookup_index| lookup_index.lookup_info.features.patterns.lookup);

    let runtime_tables = index
        .lookup_index
        .as_ref()
        .is_some_and(|lookup_index| lookup_index.runtime_tables_selector.is_some());

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

fn hydrate_verifier_index(
    mut index: PastaFpVerifierIndex,
    srs: Arc<PastaFpSrs>,
) -> PastaFpVerifierIndex {
    let feature_flags = compute_feature_flags(&index);
    let (linearization, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);
    let (endo_q, _) = poly_commitment::ipa::endos::<Pallas>();

    let w = OnceLock::new();
    let _ = w.set(zk_w(index.domain, index.zk_rows));

    let permutation_vanishing_polynomial_m = OnceLock::new();
    let _ = permutation_vanishing_polynomial_m
        .set(permutation_vanishing_polynomial(index.domain, index.zk_rows));

    index.srs = srs;
    index.w = w;
    index.endo = endo_q;
    index.permutation_vanishing_polynomial_m = permutation_vanishing_polynomial_m;
    index.linearization = linearization;
    index.powers_of_alpha = powers_of_alpha;
    index
}

fn parse_public_input(fields: &[String]) -> Result<Vec<Fp>, Box<dyn std::error::Error>> {
    fields
        .iter()
        .map(|field| {
            field
                .parse::<Fp>()
                .map_err(|()| format!("invalid public input field: {field}").into())
        })
        .collect()
}

fn srs_from_json_points(points: &[OrInfinityJson]) -> Result<PastaFpSrs, Box<dyn std::error::Error>> {
    let (h, g) = points
        .split_first()
        .ok_or("bundle SRS is empty")?;

    let h = point_hex(&point_from_json(h)?)?;
    let g = g
        .iter()
        .map(point_from_json)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(point_hex)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(serde_json::from_value(serde_json::json!({ "g": g, "h": h }))?)
}

fn point_from_json(point: &OrInfinityJson) -> Result<Vesta, Box<dyn std::error::Error>> {
    match point {
        OrInfinityJson::Infinity(label) if label == "Infinity" => Ok(Vesta::default()),
        OrInfinityJson::Infinity(label) => Err(format!("unexpected point tag: {label}").into()),
        OrInfinityJson::Finite { x, y } => {
            let x = x
                .parse::<Fq>()
                .map_err(|()| format!("invalid Vesta x coordinate: {x}"))?;
            let y = y
                .parse::<Fq>()
                .map_err(|()| format!("invalid Vesta y coordinate: {y}"))?;
            Ok(Vesta::new_unchecked(x, y))
        }
    }
}

fn point_hex(point: &Vesta) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    point
        .serialize_compressed(&mut bytes)
        .map_err(|error| format!("failed to serialize SRS point: {error}"))?;
    Ok(hex::encode(bytes))
}
