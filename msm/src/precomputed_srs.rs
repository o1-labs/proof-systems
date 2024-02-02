//! Clone of kimchi/precomputed_srs.rs but for MSM project with BN254

use std::path::PathBuf;
use std::{fs::File, io::BufReader};

use ark_ff::UniformRand;

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::{PairingProof, PairingSRS};
use poly_commitment::srs::SRS;

use crate::{Fp, MsmBN254, DOMAIN_SIZE};

/// The size of the SRS that we serialize.
pub const SERIALIZED_SRS_SIZE: u32 = 16;

/// The path of the serialized BN254 SRS.
pub fn get_bn254_srs_path() -> PathBuf {
    let base_path = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(base_path).join("../msm/msm_srs/msm_bn254.srs")
}

/// Obtains an SRS for a specific curve from disk, or generates it if absent.
pub fn get_bn254_srs(domain: EvaluationDomains<Fp>) -> PairingSRS<MsmBN254> {
    // let srs_path = get_srs_path::<G>();
    // let file =
    //     File::open(srs_path.clone()).unwrap_or_else(|_| panic!("missing SRS file: {srs_path:?}"));
    // let reader = BufReader::new(file);
    // rmp_serde::from_read(reader).unwrap()

    // Trusted setup toxic waste
    let x = Fp::rand(&mut rand::rngs::OsRng);

    let mut srs = PairingSRS::create(x, DOMAIN_SIZE);
    srs.full_srs.add_lagrange_basis(domain.d1);
    srs
}

//pub fn create_or_check_srs<G>()
//where
//    G: KimchiCurve,
//    G::BaseField: PrimeField,
//{
//    // generate SRS
//    let trapdoor = Fp::rand(&mut rand::rngs::OsRng);
//
//    let mut srs = PairingSRS::create(trapdoor, DOMAIN_SIZE);
//    srs.full_srs.add_lagrange_basis(domain.d1);
//
//    let srs = SRS::<G>::create(1 << log2_size);
//
//    // overwrite SRS if the env var is set
//    let srs_path = get_srs_path::<G>();
//    if std::env::var("SRS_OVERWRITE").is_ok() {
//        let mut file = std::fs::OpenOptions::new()
//            .create(true)
//            .write(true)
//            .open(srs_path)
//            .expect("failed to open SRS file");
//
//        let srs_bytes = rmp_serde::to_vec(&srs).unwrap();
//        file.write_all(&srs_bytes).expect("failed to write file");
//        file.flush().expect("failed to flush file");
//    }
//
//    // get SRS from disk
//    let srs_on_disk = get_srs::<G>();
//
//    // check that it matches what we just generated
//    assert_eq!(srs, srs_on_disk);
//}
