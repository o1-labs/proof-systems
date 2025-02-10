use crate::utils::encode_for_domain;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use rayon::prelude::*;
use thiserror::Error;
use tracing::instrument;

// sparse representation, keeping only the non-zero differences
#[derive(Clone, Debug, PartialEq)]
pub struct Diff<F: PrimeField> {
    pub evaluation_diffs: Vec<Vec<(usize, F)>>,
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
    pub fn create<D: EvaluationDomain<F>>(
        domain: &D,
        old: &[u8],
        new: &[u8],
    ) -> Result<Diff<F>, DiffError> {
        let old_elems: Vec<Vec<F>> = encode_for_domain(domain, old);
        let mut new_elems: Vec<Vec<F>> = encode_for_domain(domain, new);
        if old_elems.len() < new_elems.len() {
            return Err(DiffError::CapacityMismatch {
                max_number_chunks: old_elems.len(),
                attempted: new_elems.len(),
            });
        }
        if old_elems.len() > new_elems.len() {
            let padding = vec![F::zero(); domain.size()];
            new_elems.resize(old_elems.len(), padding);
        }
        Ok(Diff {
            evaluation_diffs: new_elems
                .par_iter()
                .zip(old_elems)
                .map(|(n, o)| {
                    n.iter()
                        .zip(o)
                        .enumerate()
                        .map(|(index, (a, b))| (index, *a - b))
                        .filter(|(_, x)| !x.is_zero())
                        .collect()
                })
                .collect(),
        })
    }

    #[instrument(skip_all, level = "debug")]
    pub fn as_evaluations(
        &self,
        domain: &Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>> {
        self.evaluation_diffs
            .par_iter()
            .map(|diff| {
                let mut evals = vec![F::zero(); domain.size()];
                diff.iter().for_each(|(j, val)| {
                    evals[*j] = *val;
                });
                Evaluations::from_vec_and_domain(evals, *domain)
            })
            .collect()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::utils::{chunk_size_in_bytes, min_encoding_chunks, test_utils::UserData};
    use ark_ff::Zero;
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

    fn add(mut evals: Vec<Vec<Fp>>, diff: &Diff<Fp>) -> Vec<Vec<Fp>> {
        evals
            .par_iter_mut()
            .zip(diff.evaluation_diffs.par_iter())
            .for_each(|(eval_chunk, diff_chunk)| {
                diff_chunk.iter().for_each(|(j, val)| {
                    eval_chunk[*j] += val;
                });
            });
        evals.to_vec()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]

        fn test_allow_legal_updates((UserData(xs), UserData(ys)) in
            (UserData::arbitrary().prop_flat_map(random_diff))
        ) {
            let diff = Diff::<Fp>::create(&*DOMAIN, &xs, &ys);
            prop_assert!(diff.is_ok());
            let xs_elems = encode_for_domain(&*DOMAIN, &xs);
            let ys_elems = {
                let pad = vec![Fp::zero(); DOMAIN.size()];
                let mut elems = encode_for_domain(&*DOMAIN, &ys);
                elems.resize(xs_elems.len(), pad);
                elems
            };
            let result = add(xs_elems.clone(), &diff.unwrap());
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
            let diff = Diff::<Fp>::create(&*DOMAIN, &data, &ys);
            prop_assert!(diff.is_err());
        }
    }
}
