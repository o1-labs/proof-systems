//! Clone of kimchi/precomputed_srs.rs but for MSM project with BN254

use std::path::PathBuf;
use std::{fs::File, io::BufReader};

use ark_ff::UniformRand;
use ark_serialize::Write;

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use crate::{Fp, MsmBN254, DOMAIN_SIZE};

/// The path of the serialized BN254 SRS.
pub fn get_bn254_srs_path() -> PathBuf {
    let base_path = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(base_path).join("../msm/msm_srs/msm_bn254.srs")
}

/// Tries to read the SRS from disk, otherwise panics.
pub fn read_bn254_srs_from_disk() -> PairingSRS<MsmBN254> {
    let srs_path = get_bn254_srs_path();
    let file =
        File::open(srs_path.clone()).unwrap_or_else(|_| panic!("missing SRS file: {srs_path:?}"));
    let reader = BufReader::new(file);
    rmp_serde::from_read(reader).unwrap()
}

/// Creates a BN254 SRS. If the `overwrite_srs` flag is on, or
/// `SRS_OVERWRITE` env variable is ON, also writes it into the file.
pub fn create_and_store_srs(
    overwrite_srs: bool,
    domain: EvaluationDomains<Fp>,
) -> PairingSRS<MsmBN254> {
    // Trusted setup toxic waste
    let x = Fp::rand(&mut rand::rngs::OsRng);

    let mut srs = PairingSRS::create(x, DOMAIN_SIZE);
    srs.full_srs.add_lagrange_basis(domain.d1);

    // overwrite SRS if the env var is set
    let srs_path = get_bn254_srs_path();
    if overwrite_srs || std::env::var("SRS_OVERWRITE").is_ok() {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(srs_path)
            .expect("failed to open SRS file");

        let srs_bytes = rmp_serde::to_vec(&srs).unwrap();
        file.write_all(&srs_bytes).expect("failed to write file");
        file.flush().expect("failed to flush file");
    }

    // get SRS from disk
    let _srs_on_disk = read_bn254_srs_from_disk();

    // check that it matches what we just generated
    // *TODO*!!! Equality must be defined
    //assert_eq!(srs, srs_on_disk);

    srs
}

/// Obtains an SRS for a specific curve from disk, or generates it if absent.
pub fn get_bn254_srs(domain: EvaluationDomains<Fp>) -> PairingSRS<MsmBN254> {
    let srs_path = get_bn254_srs_path();
    match File::open(srs_path.clone()) {
        Ok(file) => {
            let reader = BufReader::new(file);
            rmp_serde::from_read(reader).unwrap()
        }
        Err(_) => {
            println!("missing SRS file: {srs_path:?}");
            create_and_store_srs(true, domain)
        }
    }
}
