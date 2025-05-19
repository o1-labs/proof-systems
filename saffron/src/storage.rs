//! This file handles the storage gestion for the state replicator ;
//! The data are stored on disk in a file, and this file provide functions to
//! read the whole file (because producing a read proof requires the whole
//! polynomial) and to update dispersed chunks of data.
//!
//! Note: the encoding used for the conversion bytes <-> scalars is the `full`
//! encoding, meaning that fields elements are encoded over `F::size_in_bytes()`
//! bytes which is 32 for Pallas & Vesta.
//! Using the 31 version leads currently to inconsistency when updating if the
//! diff's new values are greater than what is representable over 31 bytes.

use crate::{diff::Diff, encoding};
use ark_ff::PrimeField;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use crate::SRS_SIZE;

pub struct Data<F: PrimeField> {
    pub data: Vec<F>,
}

/// Creates a file at `path` and fill it with `data`
/// TODO: For now, we assume the data vector is smaller than SRS_SIZE
pub fn init<F: PrimeField>(path: &str, data: &Data<F>) -> std::io::Result<()> {
    // TODO: handle the > SRS_SIZE case
    assert!(data.data.len() <= SRS_SIZE);
    let mut file = File::create(path)?;
    for x in &data.data {
        let x_bytes = encoding::decode_full(*x);
        file.write_all(&x_bytes)?
    }
    Ok(())
}

/// `read(path)` loads the whole content of the file in `path` and stores it as
/// bytes.
/// This function raises an error when the path does not exist, or if there is
/// an issue with reading.
pub fn read<F: PrimeField>(path: &str) -> std::io::Result<Data<F>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    // TODO: handle the > SRS_SIZE case (ie Vec<Vec<F>>)
    let data = encoding::encode_as_field_elements_full(&buffer);
    Ok(Data { data })
}

/// Takes a valid diff and update the file accordingly, replacing the old
/// values by the new ones at the specified indices ; the indices of the diff
/// are specified by scalars (not by bytes) and the values of the diff are the
/// new scalar value expected for the new data.
/// Note that this only update the file, not the commitment
pub fn update<F: PrimeField>(path: &str, diff: &Diff<F>) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let region_offset = diff.region * (SRS_SIZE as u64);
    let scalar_size = encoding::encoding_size_full::<F>() as u64;
    for (index, new_value) in diff.addresses.iter().zip(diff.new_values.iter()) {
        let corresponding_bytes_index = (region_offset + index) * scalar_size;
        file.seek(SeekFrom::Start(corresponding_bytes_index))?;
        let new_value_bytes = encoding::decode_full(*new_value);
        file.write_all(&new_value_bytes)?;
    }
    Ok(())
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::ScalarField;
    use kimchi_stubs::field_vector::fp::CamlFpVector;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlData {
        pub data: CamlFpVector,
    }

    // let x: Data<Fq> = Data { data: vec![Fq::one()] };
    // let caml_x: CamlData<Fq> = x.into();

    impl From<Data<ScalarField>> for CamlData {
        fn from(data: Data<ScalarField>) -> Self {
            Self {
                data: CamlFpVector::create(data.data),
            }
        }
    }

    impl From<CamlData> for Data<ScalarField> {
        fn from(caml_data: CamlData) -> Self {
            Self {
                data: caml_data.data.as_slice().into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{diff::Diff, encoding, env, storage, storage::Data, Curve, ScalarField, SRS_SIZE};
    use ark_ff::{One, UniformRand, Zero};
    use ark_poly::{univariate::DensePolynomial, Evaluations};
    use kimchi::circuits::domains::EvaluationDomains;
    use mina_curves::pasta::{Fp, Vesta};
    use once_cell::sync::Lazy;
    use poly_commitment::{ipa::SRS, SRS as _};
    use rand::Rng;
    use std::fs;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(SRS_SIZE)
        }
    });

    static DOMAIN: Lazy<EvaluationDomains<ScalarField>> =
        Lazy::new(|| EvaluationDomains::<ScalarField>::create(SRS_SIZE).unwrap());

    fn compute_comm(data: &[ScalarField]) -> Curve {
        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.to_vec(), (DOMAIN).d1).interpolate();
        SRS.commit_non_hiding(&data_poly, 1).chunks[0]
    }

    #[test]
    // Test that data commitment stays the same after reading (i.e. data stay
    // consistent through writing and reading), and test that update is
    // consistently performed in the file
    fn test_data_consistency() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        // Path of th file that will contain the test data
        let path = "./test";

        let data_bytes: Vec<u8> = (0..(SRS_SIZE * (encoding::encoding_size_full::<ScalarField>())))
            .map(|_| rng.gen())
            .collect();
        let data: Vec<ScalarField> = encoding::encode_as_field_elements_full(&data_bytes);
        let data_comm = compute_comm(&data);

        let data_struct = Data { data };

        let read_consistency = {
            let _init_storage_file = storage::init(path, &data_struct);
            let read_data_struct: Data<ScalarField> = storage::read(path).unwrap();
            let read_data_comm = compute_comm(&read_data_struct.data);

            // True if read data are the same as initial data
            Curve::eq(&data_comm, &read_data_comm)
        };

        let (data_updated, update_consistency) = {
            let diff = {
                // The number of updates is proportional to the data length,
                // but we make sure to have at least one update if the data is
                // small
                let nb_updates = std::cmp::max(data_struct.data.len() / 20, 1);
                let region = 0;
                let addresses: Vec<u64> = (0..nb_updates)
                    .map(|_| (rng.gen_range(0..data_struct.data.len() as u64)))
                    .collect();
                let mut new_values: Vec<ScalarField> =
                    addresses.iter().map(|_| Fp::rand(&mut rng)).collect();
                // The first value is replaced by a scalar that would
                // overflow 31 bytes, so the update is not consistent and the
                // test fails if this case is not handled
                new_values[0] = Fp::zero() - Fp::one();
                Diff {
                    region,
                    addresses,
                    new_values,
                }
            };

            let updated_data = &Diff::apply(&[data_struct.data], &diff)[0];
            let updated_data_comm = compute_comm(updated_data);

            let _file_update = storage::update(path, &diff);

            let updated_read_data_struct: Data<ScalarField> = storage::read(path).unwrap();
            let updated_read_data_comm = compute_comm(&updated_read_data_struct.data);

            (
                Curve::ne(&updated_data_comm, &data_comm),
                // True if read data from updated file are the same as updated data
                Curve::eq(&updated_data_comm, &updated_read_data_comm),
            )
        };

        let _remove_file = fs::remove_file(path);

        assert!(read_consistency);
        assert!(data_updated);
        assert!(update_consistency);
    }
}
