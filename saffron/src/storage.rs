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
                let pos = file.seek(SeekFrom::Current(0))?;
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
        commitment::Commitment, diff::Diff, encoding, env, storage, storage::Data, ScalarField,
        SRS_SIZE,
    };
    use ark_ff::{One, UniformRand, Zero};
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
        let mut data: Vec<ScalarField> = encoding::encode_as_field_elements_full(&data_bytes);
        // Setting the first value of data to zero will make the updated bytes
        // with the well chosen diff
        data[0] = Fp::zero();
        let data_comm = Commitment::from_data(&SRS, &data);

        let data_struct = Data { data };

        let read_consistency = {
            let _init_storage_file = storage::init(path, &data_struct);
            let read_data_struct: Data<ScalarField> = storage::read(path).unwrap();
            let read_data_comm = Commitment::from_data(&SRS, &read_data_struct.data);

            // True if read data are the same as initial data
            Commitment::eq(&data_comm, &read_data_comm)
        };

        let (data_updated, update_consistency, diff_comm_consistency) = {
            let diff = {
                // The number of updates is proportional to the data length,
                // but we make sure to have at least one update if the data is
                // small
                let nb_updates = std::cmp::max(data_struct.data.len() / 20, 1);
                let region = 0;
                let addresses: Vec<u64> = (0..nb_updates)
                    .map(|_| (rng.gen_range(0..data_struct.data.len() as u64)))
                    .collect();
                let mut diff_values: Vec<ScalarField> =
                    addresses.iter().map(|_| Fp::rand(&mut rng)).collect();
                // The first value is replaced by a scalar that would
                // overflow 31 bytes, so the update is not consistent and the
                // test fails if this case is not handled
                diff_values[0] = Fp::zero() - Fp::one();
                Diff {
                    region,
                    addresses,
                    diff_values,
                }
            };

            let updated_data = &Diff::apply(&[data_struct.data], &diff)[0];
            let updated_data_comm = Commitment::from_data(&SRS, updated_data);

            let _file_update = storage::update(path, &diff);

            let updated_read_data_struct: Data<ScalarField> = storage::read(path).unwrap();
            let updated_read_data_comm =
                Commitment::from_data(&SRS, &updated_read_data_struct.data);

            (
                // True if the data have changed because of the update
                Commitment::ne(&updated_data_comm, &data_comm),
                // True if read data from updated file are the same as updated data
                Commitment::eq(&updated_data_comm, &updated_read_data_comm),
            )
        };

        let _remove_file = fs::remove_file(path);

        assert!(read_consistency);
        assert!(data_updated);
        assert!(update_consistency);
    }
}
