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

use crate::{commitment::*, diff::Diff, encoding, utils::evals_to_polynomial};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain as R2D};
use kimchi::curve::KimchiCurve;
use poly_commitment::ipa::SRS;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use crate::SRS_SIZE;

pub struct Data<F: PrimeField> {
    pub data: Vec<F>,
}

impl<F: PrimeField> Data<F> {
    /// Returns the data correpsonding to the provided `bytes`
    pub fn of_bytes(bytes: &[u8]) -> Data<F> {
        Data {
            data: encoding::encode_as_field_elements_full(bytes),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the length of the data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns the polynomial that correspond to the data. If the data is
    /// bigger than domain's size, the additionnal points will be ignored.
    /// If the data is smaller, it is padded with zeros
    pub fn to_polynomial(&self, domain: R2D<F>) -> DensePolynomial<F> {
        use std::iter;
        let n = domain.size();
        let padded_data: Vec<F> = self
            .data
            .iter()
            .cloned()
            .chain(iter::repeat(F::zero()))
            .take(n)
            .collect();
        evals_to_polynomial(padded_data, domain)
    }

    /// Commit a `data` of length smaller than `SRS_SIZE`
    /// If greater data is provided, anything above `SRS_SIZE` is ignored
    pub fn to_commitment<G: KimchiCurve<ScalarField = F>>(&self, srs: &SRS<G>) -> Commitment<G> {
        Commitment::from_data(srs, &self.data)
    }

    /// Modifies inplace the provided data with `diff`
    pub fn apply_inplace(&mut self, diff: &Diff<F>) {
        let data_slice = std::slice::from_mut(&mut self.data);
        Diff::apply_inplace(data_slice, diff);
    }

    /// Returns a new data corresponding to the provided data with `diff` applied
    pub fn apply(&self, diff: &Diff<F>) -> Data<F> {
        let mut data = Data {
            data: self.data.clone(),
        };
        data.apply_inplace(diff);
        data
    }
}

/// Creates a file at `path` and fill it with `data`
/// TODO: For now, we assume the data vector is smaller than SRS_SIZE
pub fn init<F: PrimeField>(path: &str, data: &Data<F>) -> std::io::Result<()> {
    // TODO: handle the > SRS_SIZE case
    assert!(data.len() <= SRS_SIZE);
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
    Ok(Data::of_bytes(&buffer))
}

/// Takes a valid diff and update the file accordingly, replacing the old
/// values by the new ones at the specified indices ; the indices of the diff
/// are specified by scalars (not by bytes) and the values of the diff are the
/// new scalar value expected for the new data.
/// Note that this only update the file, not the commitment
pub fn update<F: PrimeField>(path: &str, diff: &Diff<F>) -> std::io::Result<()> {
    // Open the file in read mode to get the old value & write mode to write the new value
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let region_offset = diff.region * (SRS_SIZE as u64);
    let scalar_size = encoding::encoding_size_full::<F>() as u64;
    for (index, diff_value) in diff.addresses.iter().zip(diff.diff_values.iter()) {
        let corresponding_bytes_index = (region_offset + index) * scalar_size;
        file.seek(SeekFrom::Start(corresponding_bytes_index))?;
        let new_value: F = {
            // The old value is taken directly from the file
            let old_value: F = {
                // Save the current cursor position to be able to reset the
                // cursor after the read later
                let pos = file.stream_position()?;
                let mut old_value_bytes = vec![0u8; encoding::encoding_size_full::<F>()];
                file.read_exact(&mut old_value_bytes)?;
                // Go back to the previous position in the file, so the read value
                // will be overwritten by the new one
                file.seek(SeekFrom::Start(pos))?;
                encoding::encode(&old_value_bytes)
            };
            old_value + diff_value
        };
        let new_value_bytes = encoding::decode_full(new_value);
        file.write_all(&new_value_bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        commitment::Commitment, diff::Diff, encoding, env, storage, storage::Data, Curve,
        ScalarField, SRS_SIZE,
    };
    use ark_ff::{One, UniformRand, Zero};
    use once_cell::sync::Lazy;
    use poly_commitment::{ipa::SRS, SRS as _};
    use rand::Rng;
    use std::fs;
    use tempfile::NamedTempFile;

    static SRS: Lazy<SRS<Curve>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(SRS_SIZE)
        }
    });

    #[test]
    // Test that data commitment stays the same after reading (i.e. data stay
    // consistent through writing and reading), and test that update is
    // consistently performed in the file
    fn test_data_consistency() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Path of the file that will contain the test data
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();

        let data_bytes: Vec<u8> = (0..(SRS_SIZE * (encoding::encoding_size_full::<ScalarField>())))
            .map(|_| rng.gen())
            .collect();
        let mut data = Data::of_bytes(&data_bytes);
        // Setting the first value of data to zero will make the updated bytes
        // with the well chosen diff
        data.data[0] = ScalarField::zero();
        let data_comm = data.to_commitment(&SRS);

        let read_consistency = {
            let _init_storage_file = storage::init(path, &data);
            let read_data = storage::read(path).unwrap();
            let read_data_comm = read_data.to_commitment(&SRS);

            // True if read data are the same as initial data
            Commitment::eq(&data_comm, &read_data_comm)
        };

        let (data_updated, update_consistency, diff_comm_consistency) = {
            let diff = {
                // The number of updates is proportional to the data length,
                // but we make sure to have at least one update if the data is
                // small
                let nb_updates = std::cmp::max(data.len() / 20, 1);
                let region = 0;
                let addresses: Vec<u64> = (0..nb_updates)
                    .map(|_| (rng.gen_range(0..data.len() as u64)))
                    .collect();
                let mut diff_values: Vec<ScalarField> = addresses
                    .iter()
                    .map(|_| ScalarField::rand(&mut rng))
                    .collect();
                // The first value is replaced by a scalar that would
                // overflow 31 bytes, so the update is not consistent and the
                // test fails if this case is not handled
                diff_values[0] = ScalarField::zero() - ScalarField::one();
                Diff {
                    region,
                    addresses,
                    diff_values,
                }
            };

            let updated_data = data.apply(&diff);
            let updated_data_comm = updated_data.to_commitment(&SRS);

            let _file_update = storage::update(path, &diff);

            let updated_read_data = storage::read(path).unwrap();
            let updated_read_data_comm = updated_read_data.to_commitment(&SRS);

            let updated_diff_data_comm = data_comm.update(&SRS, diff);

            (
                // True if the data have changed because of the update
                Commitment::ne(&updated_data_comm, &data_comm),
                // True if read data from updated file are the same as updated data
                Commitment::eq(&updated_data_comm, &updated_read_data_comm),
                // True if the commitments are the same as the commitment obtained by direct diff application
                Commitment::eq(&updated_diff_data_comm, &updated_data_comm),
            )
        };

        let _remove_file = fs::remove_file(path);

        assert!(read_consistency);
        assert!(data_updated);
        assert!(update_consistency);
        assert!(diff_comm_consistency);
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::{diff::caml::*, CamlScalarVector, ScalarField};

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlSaffronData {
        pub data: CamlScalarVector,
    }

    impl From<Data<ScalarField>> for CamlSaffronData {
        fn from(data: Data<ScalarField>) -> Self {
            Self {
                data: CamlScalarVector::create(data.data),
            }
        }
    }

    impl From<CamlSaffronData> for Data<ScalarField> {
        fn from(caml_data: CamlSaffronData) -> Self {
            Self {
                data: caml_data.data.as_slice().into(),
            }
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_saffron_storage_init(
        path: String,
        data: CamlSaffronData,
    ) -> Result<(), ocaml::Error> {
        match init(&path, &data.into()) {
            Err(_) => ocaml::Error::failwith("Storage.caml_init: error in file initialisation"),
            Ok(()) => Ok(()),
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_saffron_storage_read(path: String) -> Result<CamlSaffronData, ocaml::Error> {
        match read(&path) {
            Err(e) => return Err(e.into()),
            Ok(data) => Ok(data.into()),
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_saffron_storage_update(
        path: String,
        diff: CamlSaffronDiff,
    ) -> Result<(), ocaml::Error> {
        match update(&path, &diff.into()) {
            Err(_) => ocaml::Error::failwith("Storage.caml_update: error in file initialisation"),
            Ok(()) => Ok(()),
        }
    }
}
