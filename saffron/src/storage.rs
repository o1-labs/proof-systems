//! This file handles the storage gestion for the state replicator ;
//! The data are stored on disk in a file, and this file provide functions to
//! read the whole file (because producing a read proof requires the whole
//! polynomial) and to update dispersed chunks of data.

use crate::diff::Diff;
use crate::{encoding, ScalarField};
use o1_utils::FieldHelpers;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
// use ocaml::prelude::*;   // For working with OCaml bindings
// use ocaml_gen::prelude::*; // For auto-generating OCaml bindings

use crate::SRS_SIZE;

/// Creates a file at [path] and fill it with [data]
/// TODO: For now, we assume the data vector is smaller than SRS_SIZE
// #[ocaml_gen::func]
// #[ocaml::func]
pub fn init(path: &str, data: &Vec<ScalarField>) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    for x in data {
        let x_bytes = encoding::scalar_to_bytes(*x);
        file.write_all(&x_bytes)?
    }
    Ok(())
}

/// [read(path)] loads the whole content of the file in [path] and stores it as
/// bytes.
/// This function raises an error when the path does not exist, or if there is
/// an issue with reading.
pub fn read(path: &str) -> std::io::Result<Vec<ScalarField>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    // handle the > SRS_SIZE case
    // TODO: handle error properly
    assert!(buffer.len() % ScalarField::size_in_bytes() == 0) ;
    Ok(encoding::scalars_from_bytes(&buffer))
}

/// takes a valid diff and update the file accordingly, replacing the old values by the new ones at the specified indices ; the indices of the diff are specified by scalars (not by bytes) and the values of the diff are the new scalar value expected for the new data.
/// Note that this only update the file, not the commitment
pub fn update(path: &str, diff: &Diff<ScalarField>) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let region_offset = diff.region * (SRS_SIZE as u64);
    let scalar_size = ScalarField::size_in_bytes() as u64;
    for (index, new_value) in diff.addresses.iter().zip(diff.new_values.iter()) {
        let corresponding_bytes_index = (region_offset + index) * scalar_size;
        file.seek(SeekFrom::Start(corresponding_bytes_index))?;
        let new_value_bytes = encoding::scalar_to_bytes(*new_value);
        file.write_all(&new_value_bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::diff::Diff;
    use crate::env;
    use crate::storage;
    use crate::Curve;
    use crate::ScalarField;
    use crate::SRS_SIZE;
    use ark_ff::UniformRand;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::Evaluations;
    use kimchi::circuits::domains::EvaluationDomains;
    use mina_curves::pasta::Fp;
    use mina_curves::pasta::Vesta;
    use once_cell::sync::Lazy;
    use poly_commitment::ipa::SRS;
    use poly_commitment::SRS as _;
    use rand::Rng;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(SRS_SIZE)
        }
    });

    static DOMAIN: Lazy<EvaluationDomains<ScalarField>> =
        Lazy::new(|| EvaluationDomains::<ScalarField>::create(SRS_SIZE).unwrap());

    fn compute_comm(data: &Vec<ScalarField>) -> Curve {
        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), (DOMAIN).d1).interpolate();
        SRS.commit_non_hiding(&data_poly, 1).chunks[0]
    }

    #[test]
    // Test that data commitment stays the same after reading (i.e. data stay consistent through writing and reading), and test that update is consistently performed in the file
    fn test_data_consistency() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let path = "./test";
        let data: Vec<ScalarField> = {
            let mut data = vec![];
            (0..SRS_SIZE)
                .into_iter()
                .for_each(|_| data.push(Fp::rand(&mut rng)));

            data
        };
        let data_comm = compute_comm(&data);

        let read_consistency = {
            let _init_storage_file = storage::init(path, &data);
            let read_data: Vec<ScalarField> = storage::read(path).unwrap();
            let read_data_comm = compute_comm(&read_data);

            // True if read data are the same as initial data
            Curve::eq(&data_comm, &read_data_comm)
        };

        let (data_updated, update_consistency) = {
            let diff = {
                let nb_updates = data.len() / 20;
                assert!(nb_updates > 0);
                let region = 0;
                let addresses: Vec<u64> = (0..nb_updates)
                    .map(|_| (rng.gen_range(0..data.len() as u64)))
                    .collect();
                let new_values: Vec<ScalarField> =
                    addresses.iter().map(|_| Fp::rand(&mut rng)).collect();

                Diff {
                    region,
                    addresses,
                    new_values,
                }
            };
            let updated_data = &Diff::apply(&mut [data], &diff)[0];

            let updated_data_comm = compute_comm(&updated_data);

            let _file_update = storage::update(path, &diff);

            let updated_read_data: Vec<ScalarField> = storage::read(path).unwrap();
            let updated_read_data_comm = compute_comm(&updated_read_data);

            // True if read data from updated file are the same as updated data
            (
                Curve::ne(&updated_data_comm, &data_comm),
                Curve::eq(&updated_data_comm, &updated_read_data_comm),
            )
        };
        assert!(read_consistency);
        assert!(data_updated);
        assert!(update_consistency);
    }
}
