//! This module contains recursion-related functions and structs.

use crate::verifier_index::VerifierIndex;
use ark_ec::AffineCurve;
use ark_ff::{One, Zero};
use commitment_dlog::commitment::{b_poly, b_poly_coefficients, CommitmentCurve, PolyComm};
use o1_utils::chunked_polynomial::ChunkedEvals;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

/// Alias to refer to the scalar field of a curve.
type Fr<G> = <G as AffineCurve>::ScalarField;

/// Alias to refer to the base field of a curve.
type Fq<G> = <G as AffineCurve>::BaseField;

/// Contains the previous proof's challenges which verification was deferred to the next proof.
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct Recursion<G>
where
    G: AffineCurve,
{
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub challenges: Vec<Fr<G>>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub commitment: PolyComm<G>,
}

impl<G> Recursion<G>
where
    G: CommitmentCurve,
{
    pub fn prev_chal_evals(
        &self,
        index: &VerifierIndex<G>,
        evaluation_points: &[Fr<G>],
        powers_of_eval_points_for_chunks: &[Fr<G>],
    ) -> Vec<ChunkedEvals<Fr<G>>> {
        // No need to check the correctness of poly explicitly. Its correctness is assured by the
        // checking of the inner product argument.
        let b_len = 1 << self.challenges.len();
        let mut b: Option<Vec<Fr<G>>> = None;

        (0..2)
            .map(|i| {
                let full = b_poly(&self.challenges, evaluation_points[i]);
                if index.max_poly_size == b_len {
                    return vec![full];
                }
                let mut betaacc = Fr::<G>::one();
                let diff = (index.max_poly_size..b_len)
                    .map(|j| {
                        let b_j = match &b {
                            None => {
                                let t = b_poly_coefficients(&self.challenges);
                                let res = t[j];
                                b = Some(t);
                                res
                            }
                            Some(b) => b[j],
                        };

                        let ret = betaacc * b_j;
                        betaacc *= &evaluation_points[i];
                        ret
                    })
                    .fold(Fr::<G>::zero(), |x, y| x + y);
                vec![full - (diff * powers_of_eval_points_for_chunks[i]), diff]
            })
            .collect()
    }
}

pub mod testing {
    use super::*;

    use crate::prover_index::ProverIndex;
    use ark_ff::UniformRand;
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use o1_utils::math::ceil_log2;

    pub fn new_recursion_for_testing<G>(
        index: &ProverIndex<G>,
        rng: &mut impl rand::Rng,
    ) -> Vec<Recursion<G>>
    where
        G: CommitmentCurve,
    {
        let k = ceil_log2(index.srs.g.len());
        let challenges: Vec<_> = (0..k).map(|_| Fr::<G>::rand(rng)).collect();
        let commitment = {
            let coeffs = b_poly_coefficients(&challenges);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.commit_non_hiding(&b, None)
        };
        vec![Recursion {
            challenges,
            commitment,
        }]
    }
}
