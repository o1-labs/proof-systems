//! Clone of kimchi/precomputed_srs.rs but for MSM project with BN254

use std::path::PathBuf;
use std::{fs::File, io::BufReader};

use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use crate::{BN254G2Affine, Fp, BN254, DOMAIN_SIZE};

/// The path of the serialized BN254 SRS.
pub fn get_bn254_srs_path() -> PathBuf {
    let base_path = env!("CARGO_MANIFEST_DIR");
    if base_path.is_empty() {
        println!("WARNING: BN254 precomputation: CARGO_MANIFEST_DIR is absent in release mode, can't determine orking directory. Turn off --release");
    }
    let res = PathBuf::from(base_path).join("./msm_srs/msm_bn254.srs");
    println!("BN254 SRS path: {:?}", res);
    res
}

/// Tries to read the SRS from disk, otherwise panics.
pub fn read_bn254_srs_from_disk() -> PairingSRS<BN254> {
    let srs_path = get_bn254_srs_path();
    let file =
        File::open(srs_path.clone()).unwrap_or_else(|_| panic!("missing SRS file: {srs_path:?}"));
    let reader = BufReader::new(file);
    rmp_serde::from_read(reader).unwrap()
}

// @volhovm: Serialization of G2Affine points is broken somewhere deep
// underneath. This test works for most types including G1Affine, but
// it fails for G2 while reading with 'value: InvalidData'.
// Try to find a "mode" setting -- maybe serialization is optimised, while deserialization is not. Serialize_with_mode
pub fn test_serialization() {
    let path = PathBuf::from("./test_file.srs");

    let file1 = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(path.clone())
        .expect("failed to open SRS file");
    let x = Fp::rand(&mut rand::rngs::OsRng);
    let srs: PairingSRS<BN254> = PairingSRS::create(x, DOMAIN_SIZE);

    // minimal example: a single G2 point
    let actual: BN254G2Affine = srs.verifier_srs.h;
    let _ = actual.serialize(file1);

    let file2 = File::open(path.clone()).unwrap_or_else(|_| panic!("File absent"));
    let reader = BufReader::new(file2);
    let expected: BN254G2Affine = CanonicalDeserialize::deserialize(reader).unwrap();

    assert!(expected == actual, "test_serialization() failed");
    println!("test_serialization() success");
}

/// Creates a BN254 SRS. If the `overwrite_srs` flag is on, or
/// `SRS_OVERWRITE` env variable is ON, also writes it into the file.
pub fn create_and_store_srs(
    overwrite_srs: bool,
    domain: EvaluationDomains<Fp>,
) -> PairingSRS<BN254> {
    // Trusted setup toxic waste
    let x = Fp::rand(&mut rand::rngs::OsRng);

    let mut srs: PairingSRS<BN254> = PairingSRS::create(x, DOMAIN_SIZE);
    srs.full_srs.add_lagrange_basis(domain.d1);

    // overwrite SRS if the env var is set
    let srs_path = get_bn254_srs_path();
    if overwrite_srs || std::env::var("SRS_OVERWRITE").is_ok() {
        println!("Writing the SRS");
        // Create parent directories
        std::fs::create_dir_all(srs_path.parent().unwrap()).unwrap();
        // Open/create the file
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(srs_path)
            .expect("failed to open SRS file");

        let srs_bytes = rmp_serde::to_vec(&srs).unwrap();
        file.write_all(&srs_bytes).expect("failed to write file");
        file.flush().expect("failed to flush file");
    }

    println!("Reading the SRS from the disk to double check");
    // get SRS from disk
    let srs_on_disk = read_bn254_srs_from_disk();

    // check that it matches what we just generated
    // *TODO*!!! Equality must be defined
    assert_eq!(srs, srs_on_disk);

    srs
}

/// Obtains an SRS for a specific curve from disk, or generates it if absent.
pub fn get_bn254_srs(domain: EvaluationDomains<Fp>) -> PairingSRS<BN254> {
    // Temporarily just generate it from scratch since SRS serialization is
    // broken. See test_serialization.
    let trapdoor = Fp::rand(&mut rand::rngs::OsRng);
    let mut srs = PairingSRS::create(trapdoor, DOMAIN_SIZE);
    srs.full_srs.add_lagrange_basis(domain.d1);
    srs

    //let srs_path = get_bn254_srs_path();
    //match File::open(srs_path.clone()) {
    //    Ok(file) => {
    //        let reader = BufReader::new(file);
    //        rmp_serde::from_read(reader).unwrap()
    //    }
    //    Err(_) => {
    //        println!("missing SRS file: {srs_path:?}. Will create a new SRS...");
    //        create_and_store_srs(true, domain)
    //    }
    //}
}
