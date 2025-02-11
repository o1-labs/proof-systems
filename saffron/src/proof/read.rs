use crate::blob::FieldBlob;
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations};
use poly_commitment::commitment::CommitmentCurve;
use rayon::prelude::*;

pub struct IndexQuery {
    chunks: Vec<Vec<usize>>,
}

pub fn make_constraint_polys<G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>>(
    domain: &D,
    query: IndexQuery,
    blob: &FieldBlob<G>,
) -> Vec<DensePolynomial<G::ScalarField>> {
    query
        .chunks
        .into_par_iter()
        .zip(blob.chunks.par_iter())
        .map(|(indices, poly)| {
            let mut evals = poly.evaluate_over_domain_by_ref(*domain);
            let selector = {
                let mut v = vec![G::ScalarField::zero(); domain.size()];
                indices.iter().for_each(|i| {
                    v[*i] = G::ScalarField::one();
                });
                Evaluations::from_vec_and_domain(v, *domain)
            };
            evals *= &selector;
            evals.interpolate()
        })
        .collect()
}
