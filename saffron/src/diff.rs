use crate::encoding::encode_for_domain;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use rayon::prelude::*;
use thiserror::Error;
use tracing::instrument;

/// Diff request pointing to a single commitment.
#[derive(Clone, Debug, PartialEq)]
pub struct Diff<F: PrimeField> {
    /// Which commitment within a group of commitments representing
    /// the data is the diff for.
    pub region: u64,
    /// A list of unique addresses, each ∈ [0, SRS_SIZE]
    pub addresses: Vec<u64>,
    /// A list of `new_value - old_values`, each corresponding to address in `addresses`
    pub diff_values: Vec<F>,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum DiffError {
    #[error("Capacity Mismatch: maximum number of chunks is {max_number_chunks}, attempted to create {attempted}")]
    CapacityMismatch {
        max_number_chunks: usize,
        attempted: usize,
    },
}

impl<F: PrimeField> Diff<F> {
    #[instrument(skip_all, level = "debug")]
    pub fn create_from_field_elements(
        old: &Vec<Vec<F>>,
        new: &Vec<Vec<F>>,
    ) -> Result<Vec<Diff<F>>, DiffError> {
        if old.len() != new.len() {
            return Err(DiffError::CapacityMismatch {
                max_number_chunks: old.len(),
                attempted: new.len(),
            });
        }
        let diffs: Vec<Diff<_>> = old
            .par_iter()
            .zip(new)
            .enumerate()
            .filter_map(|(region, (o, n))| {
                let mut addresses: Vec<u64> = vec![];
                let mut diff_values: Vec<F> = vec![];
                for (index, (o_elem, n_elem)) in o.iter().zip(n.iter()).enumerate() {
                    if o_elem != n_elem {
                        addresses.push(index as u64);
                        diff_values.push(*n_elem - *o_elem);
                    }
                }

                if !addresses.is_empty() {
                    Some(Diff {
                        region: region as u64,
                        addresses,
                        diff_values,
                    })
                } else {
                    // do not record a diff with empty changes
                    None
                }
            })
            .collect();

        Ok(diffs)
    }

    #[instrument(skip_all, level = "debug")]
    pub fn create_from_bytes<D: EvaluationDomain<F>>(
        domain: &D,
        old: &[u8],
        new: &[u8],
    ) -> Result<Vec<Diff<F>>, DiffError> {
        let old_elems: Vec<Vec<F>> = encode_for_domain(domain.size(), old);
        let new_elems: Vec<Vec<F>> = encode_for_domain(domain.size(), new);
        Self::create_from_field_elements(&old_elems, &new_elems)
    }

    /// Updates the data with the provided diff, replacing old values at
    /// specified addresses by corresponding new ones
    pub fn apply_inplace(data: &mut [Vec<F>], diff: &Diff<F>) {
        for (addr, diff_value) in diff.addresses.iter().zip(diff.diff_values.iter()) {
            data[diff.region as usize][*addr as usize] += *diff_value;
        }
    }

    /// Returns a new vector that contains the data updated with the specified
    /// diff
    pub fn apply(data: &[Vec<F>], diff: &Diff<F>) -> Vec<Vec<F>> {
        let mut data = data.to_vec();
        Self::apply_inplace(&mut data, diff);
        data
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::utils::{chunk_size_in_bytes, min_encoding_chunks, test_utils::UserData};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;
    use rand::Rng;

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
        Lazy::new(|| Radix2EvaluationDomain::new(1 << 16).unwrap());

    pub fn randomize_data(threshold: f64, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        data.iter()
            .map(|b| {
                let n = rng.gen::<f64>();
                if n < threshold {
                    rng.gen::<u8>()
                } else {
                    *b
                }
            })
            .collect()
    }

    pub fn random_diff(UserData(xs): UserData) -> BoxedStrategy<(UserData, UserData)> {
        let n_chunks = min_encoding_chunks(&*DOMAIN, &xs);
        let max_byte_len = n_chunks * chunk_size_in_bytes(&*DOMAIN);
        (0.0..=1.0, 0..=max_byte_len)
            .prop_flat_map(move |(threshold, n)| {
                let mut ys = randomize_data(threshold, &xs);
                // NOTE: n could be less than xs.len(), in which case this is just truncation
                ys.resize_with(n, rand::random);
                Just((UserData(xs.clone()), UserData(ys)))
            })
            .boxed()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]

        fn test_allow_legal_diff((UserData(xs), UserData(ys)) in
            (UserData::arbitrary().prop_flat_map(random_diff))
        ) {
            let min_len = xs.len().min(ys.len());
            let (xs, ys) = (&xs[..min_len], &ys[..min_len]) ;
            let diffs = Diff::<Fp>::create_from_bytes(&*DOMAIN, xs, ys);
            prop_assert!(diffs.is_ok());
            let diffs = diffs.unwrap();

            let xs_elems = encode_for_domain(DOMAIN.size(), xs);
            let ys_elems = encode_for_domain(DOMAIN.size(), ys);
            assert!(xs_elems.len() == ys_elems.len());

            let mut result = xs_elems.clone();
            for diff in diffs.into_iter() {
                Diff::apply_inplace(&mut result, &diff);
            }
            prop_assert_eq!(result, ys_elems);
        }
    }

    // Check that we CAN'T construct a diff that requires more polynomial chunks than the original data
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_cannot_construct_bad_diff(
            (threshold, (UserData(data), UserData(mut extra))) in (
                0.0..1.0,
                UserData::arbitrary().prop_flat_map(|UserData(d1)| {
                    UserData::arbitrary()
                        .prop_filter_map(
                            "length constraint", {
                            move |UserData(d2)| {
                                let combined = &[d1.as_slice(), d2.as_slice()].concat();
                                if min_encoding_chunks(&*DOMAIN, &d1) <
                                   min_encoding_chunks(&*DOMAIN,  combined) {
                                    Some((UserData(d1.clone()), UserData(d2)))
                                } else {
                                    None
                                }
                            }
                        }
                    )
                })
            )
        ) {
            let mut ys = randomize_data(threshold, &data);
            ys.append(&mut extra);
            let diff = Diff::<Fp>::create_from_bytes(&*DOMAIN, &data, &ys);
            prop_assert!(diff.is_err());
        }
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use kimchi_stubs::arkworks::CamlFp;
    use mina_curves::pasta::Fp;
    // pub use caml::CamlDiff;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    // TODO: Note the current implementation of Diff in OCaml does not involve region yet
    pub struct CamlSingleDiff {
        address: ocaml::Uint,
        old_value: CamlFp,
        new_value: CamlFp,
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlDiff {
        diff: Vec<CamlSingleDiff>,
    }

    impl From<CamlDiff> for Diff<Fp> {
        fn from(caml_diff: CamlDiff) -> Diff<Fp> {
            Diff {
                // TODO: in our current version with 1 commitment / Data / Contract, region is always set to 0
                region: 0u64,
                addresses: caml_diff.diff.iter().map(|x| x.address as u64).collect(),
                diff_values: caml_diff
                    .diff
                    .iter()
                    .map(|x| {
                        let new: Fp = x.new_value.into();
                        let old: Fp = x.old_value.into();
                        new - old
                    })
                    .collect(),
            }
        }
    }
}

// This is needed to export CamlDiff in storage::ocaml
#[cfg(feature = "ocaml_types")]
pub use caml::CamlDiff;
