//! Clone of kimchi/precomputed_srs.rs but for MSM project with BN254

use crate::{Fp, BN254, DOMAIN_SIZE};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::Write;
use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::{kzg::PairingSRS, precomputed_srs::TestSRS, SRS as _};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, path::PathBuf};

/// A clone of the `PairingSRS` that is serialized in a test-optimised way.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestPairingSRS<Pair: Pairing> {
    pub full_srs: TestSRS<Pair::G1Affine>,
    pub verifier_srs: TestSRS<Pair::G2Affine>,
}

impl<Pair: Pairing> From<PairingSRS<Pair>> for TestPairingSRS<Pair> {
    fn from(value: PairingSRS<Pair>) -> Self {
        TestPairingSRS {
            full_srs: From::from(value.full_srs),
            verifier_srs: From::from(value.verifier_srs),
        }
    }
}

impl<Pair: Pairing> From<TestPairingSRS<Pair>> for PairingSRS<Pair> {
    fn from(value: TestPairingSRS<Pair>) -> Self {
        PairingSRS {
            full_srs: From::from(value.full_srs),
            verifier_srs: From::from(value.verifier_srs),
        }
    }
}

/// Obtains an SRS for a specific curve from disk, or generates it if absent.
pub fn get_bn254_srs(domain: EvaluationDomains<Fp>) -> PairingSRS<BN254> {
    let srs = if domain.d1.size as usize == DOMAIN_SIZE {
        read_bn254_srs_from_disk(get_bn254_srs_path())
    } else {
        PairingSRS::create(domain.d1.size as usize)
    };
    srs.full_srs.get_lagrange_basis(domain.d1); // not added if already present.
    srs
}

/// The path of the serialized BN254 SRS, inside this repo.
pub fn get_bn254_srs_path() -> PathBuf {
    let base_path = env!("CARGO_MANIFEST_DIR");
    if base_path.is_empty() {
        println!("WARNING: BN254 precomputation: CARGO_MANIFEST_DIR is absent, can't determine working directory. It is sometimes absent in release mode.");
    }
    PathBuf::from(base_path).join("../srs/test_bn254.srs")
}

/// Tries to read the SRS from disk, otherwise panics. Returns the
/// value without Lagrange basis.
fn read_bn254_srs_from_disk(srs_path: PathBuf) -> PairingSRS<BN254> {
    let file =
        File::open(srs_path.clone()).unwrap_or_else(|_| panic!("missing SRS file: {srs_path:?}"));
    let reader = BufReader::new(file);
    let srs: TestPairingSRS<BN254> = rmp_serde::from_read(reader).unwrap();
    From::from(srs)
}

/// Creates a BN254 SRS. If the `overwrite_srs` flag is on, or
/// `SRS_OVERWRITE` env variable is ON, also writes it into the file.
fn create_and_store_srs_with_path(
    force_overwrite: bool,
    domain_size: usize,
    srs_path: PathBuf,
) -> PairingSRS<BN254> {
    // We generate with a fixed-seed RNG, only used for testing.
    let mut rng = &mut StdRng::from_seed([42u8; 32]);
    let trapdoor = Fp::rand(&mut rng);
    let srs = PairingSRS::create_trusted_setup_with_toxic_waste(trapdoor, domain_size);

    for sub_domain_size in 1..=domain_size {
        let domain = EvaluationDomains::<Fp>::create(sub_domain_size).unwrap();
        srs.full_srs.get_lagrange_basis(domain.d1);
    }

    // overwrite SRS if the env var is set
    if force_overwrite || std::env::var("SRS_OVERWRITE").is_ok() {
        // Create parent directories
        std::fs::create_dir_all(srs_path.parent().unwrap()).unwrap();
        // Open/create the file
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(srs_path.clone())
            .expect("failed to open SRS file");

        let test_srs: TestPairingSRS<BN254> = From::from(srs.clone());
        let srs_bytes = rmp_serde::to_vec(&test_srs).unwrap();
        file.write_all(&srs_bytes).expect("failed to write file");
        file.flush().expect("failed to flush file");
    }

    // get SRS from disk
    let srs_on_disk = read_bn254_srs_from_disk(srs_path);

    // check that it matches what we just generated
    assert_eq!(srs, srs_on_disk);

    srs
}

/// Creates and writes the SRS into `get_bn254_srs_path()`.
pub fn create_and_store_srs(force_overwrite: bool, domain_size: usize) -> PairingSRS<BN254> {
    let srs_path = get_bn254_srs_path();
    create_and_store_srs_with_path(force_overwrite, domain_size, srs_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Creates or checks the real full-sized SRS. Only overwrites
    /// with the ENV flag.
    pub fn heavy_test_create_or_check_srs() {
        let domain_size = DOMAIN_SIZE;
        create_and_store_srs_with_path(false, domain_size, get_bn254_srs_path());
    }

    #[test]
    /// Fast test for a small-sized SRS. Always writes & reads.
    pub fn check_bn256_srs_serialization() {
        let domain_size = 1 << 8;
        let test_srs_path = PathBuf::from("/tmp/test_bn254.srs");
        create_and_store_srs_with_path(true, domain_size, test_srs_path);
    }

    #[test]
    /// Checks if `get_bn254_srs` does not fail. Can be used for
    /// time-profiling.
    pub fn check_get_bn254_srs() {
        let domain_size = DOMAIN_SIZE;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();
        get_bn254_srs(domain);
    }
}
