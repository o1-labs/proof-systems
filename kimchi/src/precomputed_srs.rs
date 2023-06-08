//! To prover and verify proofs you need a [Structured Reference String](https://www.cryptologie.net/article/560/zk-faq-whats-a-trusted-setup-whats-a-structured-reference-string-whats-toxic-waste/) (SRS).
//! The generation of this SRS is quite expensive, so we provide a pre-generated SRS in this repo.
//! Specifically, two of them, one for each pasta curve.
//!
//! We generate the SRS within the test in this module.
//! If you modify the SRS, you will need to regenerate the SRS by passing the `SRS_OVERWRITE` env var.

use crate::curve::KimchiCurve;
use poly_commitment::srs::SRS;
use std::io::BufReader;
#[cfg(test)]
use std::path::PathBuf;

/// The size of the SRS that we serialize.
pub const SERIALIZED_SRS_SIZE: u32 = 16;

/// The path of the serialized SRS.
#[cfg(test)]
fn get_srs_path<G: KimchiCurve>() -> PathBuf {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").expect("failed to get manifest path");
    PathBuf::from(base_path)
        .join("../srs")
        .join(format!("{}.srs", G::NAME))
}

/// Obtains an SRS for a specific curve from disk.
pub fn get_srs2<G>() -> Option<SRS<G>>
where
    G: KimchiCurve,
{
    let srs = G::precomputed_srs()?;
    let reader = BufReader::new(srs);
    match rmp_serde::from_read(reader) {
        Ok(srs) => Some(srs),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use ark_serialize::Write;
    use mina_curves::pasta::{Pallas, Vesta};

    fn create_or_check_srs<G>(log2_size: u32)
    where
        G: KimchiCurve,
        G::BaseField: PrimeField,
    {
        // generate SRS
        let srs = SRS::<G>::create(1 << log2_size);

        // overwrite SRS if the env var is set
        let srs_path = get_srs_path::<G>();
        if std::env::var("SRS_OVERWRITE").is_ok() {
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
        let srs_on_disk = get_srs2::<G>().unwrap();

        // check that it matches what we just generated
        assert_eq!(srs, srs_on_disk);
    }

    /// This test checks that the two serialized SRS on disk are correct.
    #[test]
    pub fn test_srs_serialization() {
        create_or_check_srs::<Vesta>(SERIALIZED_SRS_SIZE);
        create_or_check_srs::<Pallas>(SERIALIZED_SRS_SIZE);
    }
}
