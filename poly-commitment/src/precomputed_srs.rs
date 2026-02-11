//! Pre-generated SRS (Structured Reference String) for proofs.
//!
//! To prove and verify proofs you need a [Structured Reference
//! String](https://www.cryptologie.net/article/560/zk-faq-whats-a-trusted-setup-whats-a-structured-reference-string-whats-toxic-waste/)
//! (SRS).
//! The generation of this SRS is quite expensive, so we provide a pre-generated
//! SRS in this repo.
//! Specifically, two of them, one for each pasta curve.
//!
//! We generate the SRS within the test in this module.
//! If you modify the SRS, you will need to regenerate the SRS by passing the
//! `SRS_OVERWRITE` env var.

use crate::{hash_map_cache::HashMapCache, ipa::SRS, CommitmentCurve, PolyComm};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::named::NamedCurve;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

/// We store several different types of SRS objects. This enum parameterizes
/// them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StoredSRSType {
    Test,
    Prod,
}

/// A clone of the SRS struct that is used for serialization, in a
/// test-optimised way.
///
/// NB: Serialization of these fields is unchecked (and fast). If you
/// want to make sure the data is checked on deserialization, this code
/// must be changed; or you can check it externally.
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "G: CanonicalDeserialize + CanonicalSerialize")]
pub struct TestSRS<G> {
    /// The vector of group elements for committing to polynomials in
    /// coefficient form.
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAsUnchecked>")]
    pub g: Vec<G>,

    /// A group element used for blinding commitments
    #[serde_as(as = "o1_utils::serialization::SerdeAsUnchecked")]
    pub h: G,

    /// Commitments to Lagrange bases, per domain size
    #[serde_as(as = "HashMap<_,Vec<PolyComm<o1_utils::serialization::SerdeAsUnchecked>>>")]
    pub lagrange_bases: HashMap<usize, Vec<PolyComm<G>>>,
}

impl<G: Clone> From<SRS<G>> for TestSRS<G> {
    fn from(value: SRS<G>) -> Self {
        Self {
            g: value.g,
            h: value.h,
            lagrange_bases: value.lagrange_bases.into(),
        }
    }
}

impl<G> From<TestSRS<G>> for SRS<G> {
    fn from(value: TestSRS<G>) -> Self {
        Self {
            g: value.g,
            h: value.h,
            lagrange_bases: HashMapCache::new_from_hashmap(value.lagrange_bases),
        }
    }
}

/// The size of the SRS that we serialize.
pub const SERIALIZED_SRS_SIZE: u32 = 16;

/// The path of the serialized SRS.
fn get_srs_path<G: NamedCurve>(srs_type: StoredSRSType) -> PathBuf {
    let test_prefix: String = (match srs_type {
        StoredSRSType::Test => "test_",
        StoredSRSType::Prod => "",
    })
    .to_owned();
    let base_path = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(base_path)
        .join("../srs")
        .join(test_prefix + &format!("{}.srs", G::NAME))
}

/// Generic SRS getter function.
///
/// # Panics
///
/// Panics if the SRS file does not exist on disk or cannot be
/// deserialized.
#[must_use]
pub fn get_srs_generic<G>(srs_type: StoredSRSType) -> SRS<G>
where
    G: NamedCurve + CommitmentCurve,
{
    let srs_path = get_srs_path::<G>(srs_type);
    let file = File::open(srs_path.clone())
        .unwrap_or_else(|_| panic!("missing SRS file: {}", srs_path.display()));
    let reader = BufReader::new(file);
    match srs_type {
        StoredSRSType::Test => {
            let test_srs: TestSRS<G> = rmp_serde::from_read(reader).unwrap();
            From::from(test_srs)
        }
        StoredSRSType::Prod => rmp_serde::from_read(reader).unwrap(),
    }
}

/// Obtains an SRS for a specific curve from disk.
///
/// # Panics
///
/// Panics if the SRS does not exist on disk or cannot be deserialized.
#[must_use]
pub fn get_srs<G>() -> SRS<G>
where
    G: NamedCurve + CommitmentCurve,
{
    get_srs_generic(StoredSRSType::Prod)
}

/// Obtains a Test SRS for a specific curve from disk.
///
/// # Panics
///
/// Panics if the SRS does not exist on disk or cannot be deserialized.
#[must_use]
pub fn get_srs_test<G>() -> SRS<G>
where
    G: NamedCurve + CommitmentCurve,
{
    get_srs_generic(StoredSRSType::Test)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{hash_map_cache::HashMapCache, SRS as _};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_serialize::Write;
    use hex;
    use mina_curves::pasta::{Pallas, Vesta};

    fn test_regression_serialization_srs_with_generators<G: AffineRepr>(exp_output: &str) {
        let h = G::generator();
        let g = vec![h];
        let lagrange_bases = HashMapCache::new();
        let srs = SRS::<G> {
            g,
            h,
            lagrange_bases,
        };
        let srs_bytes = rmp_serde::to_vec(&srs).unwrap();
        let output = hex::encode(srs_bytes);
        assert_eq!(output, exp_output);
    }

    #[test]
    fn test_regression_serialization_srs_with_generators_vesta() {
        // This is the same as Pallas as we encode the coordinate x only.
        // Generated with commit 4c69a4defdb109b94f1124fe93283e728f1d8758
        let exp_output = "9291c421010000000000000000000000000000000000000000000000000000000000000000c421010000000000000000000000000000000000000000000000000000000000000000";
        test_regression_serialization_srs_with_generators::<Vesta>(exp_output);
    }

    #[test]
    fn test_regression_serialization_srs_with_generators_pallas() {
        // This is the same as Pallas as we encode the coordinate x only.
        // Generated with commit 4c69a4defdb109b94f1124fe93283e728f1d8758
        let exp_output = "9291c421010000000000000000000000000000000000000000000000000000000000000000c421010000000000000000000000000000000000000000000000000000000000000000";
        test_regression_serialization_srs_with_generators::<Pallas>(exp_output);
    }

    fn create_or_check_srs<G>(log2_size: u32, srs_type: StoredSRSType)
    where
        G: NamedCurve + CommitmentCurve,
        G::BaseField: PrimeField,
    {
        // generate SRS
        let domain_size = 1 << log2_size;
        let srs = SRS::<G>::create(domain_size);

        // Test SRS objects have Lagrange bases precomputed
        if srs_type == StoredSRSType::Test {
            // FIXME we should iterate by powers of 2, instead we iterate over all the integers? why?
            for sub_domain_size in 1..=domain_size {
                let domain = Radix2EvaluationDomain::new(sub_domain_size).unwrap();
                srs.get_lagrange_basis(domain);
            }
        }

        // overwrite SRS if the env var is set
        let srs_path = get_srs_path::<G>(srs_type);
        if std::env::var("SRS_OVERWRITE").is_ok() {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(srs_path)
                .expect("failed to open SRS file");

            let srs_bytes = match srs_type {
                StoredSRSType::Test => {
                    let srs: TestSRS<G> = From::from(srs.clone());
                    rmp_serde::to_vec(&srs).unwrap()
                }
                StoredSRSType::Prod => rmp_serde::to_vec(&srs).unwrap(),
            };

            file.write_all(&srs_bytes).expect("failed to write file");
            file.flush().expect("failed to flush file");
        }

        // get SRS from disk
        let srs_on_disk: SRS<G> = get_srs_generic::<G>(srs_type);

        // check that it matches what we just generated
        assert_eq!(srs, srs_on_disk);
    }

    /// Checks if `get_srs` (prod) succeeds for Pallas. Can be used for time-profiling.
    #[test]
    pub fn heavy_check_get_srs_prod_pallas() {
        let _ = get_srs::<Pallas>();
    }

    /// Checks if `get_srs` (prod) succeeds for Vesta. Can be used for time-profiling.
    #[test]
    pub fn heavy_check_get_srs_prod_vesta() {
        let _ = get_srs::<Vesta>();
    }

    /// Checks if `get_srs` (test) succeeds for Pallas. Can be used for time-profiling.
    #[test]
    pub fn check_get_srs_test_pallas() {
        let _ = get_srs_test::<Pallas>();
    }

    /// Checks if `get_srs` (test) succeeds for Vesta. Can be used for time-profiling.
    #[test]
    pub fn check_get_srs_test_vesta() {
        let _ = get_srs_test::<Vesta>();
    }

    /// This test checks that the two serialized SRS on disk are correct.
    #[test]
    pub fn heavy_test_srs_serialization() {
        create_or_check_srs::<Vesta>(SERIALIZED_SRS_SIZE, StoredSRSType::Prod);
        create_or_check_srs::<Pallas>(SERIALIZED_SRS_SIZE, StoredSRSType::Prod);
        create_or_check_srs::<Vesta>(SERIALIZED_SRS_SIZE, StoredSRSType::Test);
        create_or_check_srs::<Pallas>(SERIALIZED_SRS_SIZE, StoredSRSType::Test);
    }
}
