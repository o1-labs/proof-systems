use crate::utils::encode_for_domain;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Diff<F: PrimeField> {
    pub evaluation_diffs: Vec<Vec<F>>,
}

impl<F: PrimeField> Diff<F> {

  pub fn create<D: EvaluationDomain<F>>(
      domain: &D,
      old: &[u8],
      new: &[u8],
  ) -> Diff<F> {
      let old_elems: Vec<Vec<F>> = encode_for_domain(domain, old);
      let new_elems: Vec<Vec<F>> = encode_for_domain(domain, new);
      Diff {
          evaluation_diffs: new_elems
              .par_iter()
              .zip(old_elems)
              .map(|(n, o)| n.iter().zip(o).map(|(a, b)| *a - b).collect())
              .collect(),
      }
  }
}
