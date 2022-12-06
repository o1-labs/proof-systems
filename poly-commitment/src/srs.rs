//! This module implements the Marlin structured reference string primitive

use crate::commitment::CommitmentCurve;
use crate::PolyComm;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use blake2::{Blake2b512, Digest};
use groupmap::GroupMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::array;
use std::cmp::min;
use std::collections::HashMap;

#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SRS<G: CommitmentCurve> {
    /// The vector of group elements for committing to polynomials in coefficient form
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub g: Vec<G>,
    /// A group element used for blinding commitments
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub h: G,

    // TODO: the following field should be separated, as they are optimization values
    /// Commitments to Lagrange bases, per domain size
    #[serde(skip)]
    pub lagrange_bases: HashMap<usize, Vec<PolyComm<G>>>,
}

pub fn endos<G: CommitmentCurve>() -> (G::BaseField, G::ScalarField)
where
    G::BaseField: PrimeField,
{
    let endo_q: G::BaseField = mina_poseidon::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r: G::ScalarField = mina_poseidon::sponge::endo_coefficient();
        let t = G::prime_subgroup_generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = G::of_coordinates(x * endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into_projective() {
            potential_endo_r
        } else {
            potential_endo_r * potential_endo_r
        }
    };
    (endo_q, endo_r)
}

fn point_of_random_bytes<G: CommitmentCurve>(map: &G::Map, random_bytes: &[u8]) -> G
where
    G::BaseField: PrimeField,
{
    // packing in bit-representation
    const N: usize = 31;
    let mut bits = [false; 8 * N];
    for i in 0..N {
        for j in 0..8 {
            bits[8 * i + j] = (random_bytes[i] >> j) & 1 == 1;
        }
    }

    let n = <G::BaseField as PrimeField>::BigInt::from_bits_be(&bits);
    let t = G::BaseField::from_repr(n).expect("packing code has a bug");
    let (x, y) = map.to_group(t);
    G::of_coordinates(x, y)
}

impl<G: CommitmentCurve> SRS<G>
where
    G::BaseField: PrimeField,
{
    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    /// Compute commitments to the lagrange basis corresponding to the given domain and
    /// cache them in the SRS
    pub fn add_lagrange_basis(&mut self, domain: D<G::ScalarField>) {
        let n = domain.size();

        if self.lagrange_bases.contains_key(&n) {
            return;
        }

        // Let V be a vector space over the field F.
        //
        // Given
        // - a domain [ 1, w, w^2, ..., w^{n - 1} ]
        // - a vector v := [ v_0, ..., v_{n - 1} ] in V^n
        //
        // the FFT algorithm computes the matrix application
        //
        // u = M(w) * v
        //
        // where
        // M(w) =
        //   1 1       1           ... 1
        //   1 w       w^2         ... w^{n-1}
        //   ...
        //   1 w^{n-1} (w^2)^{n-1} ... (w^{n-1})^{n-1}
        //
        // The IFFT algorithm computes
        //
        // v = M(w)^{-1} * u
        //
        // Let's see how we can use this algorithm to compute the lagrange basis
        // commitments.
        //
        // Let V be the vector space F[x] of polynomials in x over F.
        // Let v in V be the vector [ L_0, ..., L_{n - 1} ] where L_i is the i^{th}
        // normalized Lagrange polynomial (where L_i(w^j) = j == i ? 1 : 0).
        //
        // Consider the rows of M(w) * v. Let me write out the matrix and vector so you
        // can see more easily.
        //
        //   | 1 1       1           ... 1               |   | L_0     |
        //   | 1 w       w^2         ... w^{n-1}         | * | L_1     |
        //   | ...                                       |   | ...     |
        //   | 1 w^{n-1} (w^2)^{n-1} ... (w^{n-1})^{n-1} |   | L_{n-1} |
        //
        // The 0th row is L_0 + L1 + ... + L_{n - 1}. So, it's the polynomial
        // that has the value 1 on every element of the domain.
        // In other words, it's the polynomial 1.
        //
        // The 1st row is L_0 + w L_1 + ... + w^{n - 1} L_{n - 1}. So, it's the
        // polynomial which has value w^i on w^i.
        // In other words, it's the polynomial x.
        //
        // In general, you can see that row i is in fact the polynomial x^i.
        //
        // Thus, M(w) * v is the vector u, where u = [ 1, x, x^2, ..., x^n ]
        //
        // Therefore, the IFFT algorithm, when applied to the vector u (the standard
        // monomial basis) will yield the vector v of the (normalized) Lagrange polynomials.
        //
        // Now, because the polynomial commitment scheme is additively homomorphic, and
        // because the commitment to the polynomial x^i is just self.g[i], we can obtain
        // commitments to the normalized Lagrange polynomials by applying IFFT to the
        // vector self.g[0..n].
        //
        //
        // Further still, we can do the same trick for 'chunked' polynomials.
        //
        // Recall that a chunked polynomial is some f of degree k*n - 1 with
        // f(x) = f_0(x) + x^n f_1(x) + ... + x^{(k-1) n} f_{k-1}(x)
        // where each f_i has degree n-1.
        //
        // In the above, if we set u = [ 1, x^2, ... x^{n-1}, 0, 0, .., 0 ]
        // then we effectively 'zero out' any polynomial terms higher than x^{n-1}, leaving
        // us with the 'partial Lagrange polynomials' that contribute to f_0.
        //
        // Similarly, u = [ 0, 0, ..., 0, 1, x^2, ..., x^{n-1}, 0, 0, ..., 0] with n leading
        // zeros 'zeroes out' all terms except the 'partial Lagrange polynomials' that
        // contribute to f_1, and likewise for each f_i.
        //
        // By computing each of these, and recollecting the terms as a vector of polynomial
        // commitments, we obtain a chunked commitment to the L_i polynomials.
        let srs_size = self.g.len();
        let num_unshifteds = (n + srs_size - 1) / srs_size;
        let mut unshifted = Vec::with_capacity(num_unshifteds);

        // For each chunk
        for i in 0..num_unshifteds {
            // Initialize the vector with zero curve points
            let mut lg: Vec<<G as AffineCurve>::Projective> =
                vec![<G as AffineCurve>::Projective::zero(); n];
            // Overwrite the terms corresponding to that chunk with the SRS curve points
            let start_offset = i * srs_size;
            let num_terms = min((i + 1) * srs_size, n) - start_offset;
            for j in 0..num_terms {
                lg[start_offset + j] = self.g[j].into_projective()
            }
            // Apply the IFFT
            domain.ifft_in_place(&mut lg);
            <G as AffineCurve>::Projective::batch_normalization(lg.as_mut_slice());
            // Append the 'partial Langrange polynomials' to the vector of unshifted chunks
            unshifted.push(lg)
        }

        // If the srs size does not exactly divide the domain size
        let shifted: Option<Vec<<G as AffineCurve>::Projective>> =
            if n < srs_size || num_unshifteds * srs_size == n {
                None
            } else {
                // Initialize the vector to zero
                let mut lg: Vec<<G as AffineCurve>::Projective> =
                    vec![<G as AffineCurve>::Projective::zero(); n];
                // Overwrite the terms corresponding to the final chunk with the SRS curve points
                // shifted to the right
                let start_offset = (num_unshifteds - 1) * srs_size;
                let num_terms = n - start_offset;
                let srs_start_offset = srs_size - num_terms;
                for j in 0..num_terms {
                    lg[start_offset + j] = self.g[srs_start_offset + j].into_projective()
                }
                // Apply the IFFT
                domain.ifft_in_place(&mut lg);
                <G as AffineCurve>::Projective::batch_normalization(lg.as_mut_slice());
                Some(lg)
            };

        let chunked_commitments: Vec<_> = (0..n)
            .map(|i| PolyComm {
                unshifted: unshifted.iter().map(|v| v[i].into_affine()).collect(),
                shifted: shifted.as_ref().map(|v| v[i].into_affine()),
            })
            .collect();
        self.lagrange_bases.insert(n, chunked_commitments);
    }

    /// This function creates SRS instance for circuits with number of rows up to `depth`.
    pub fn create(depth: usize) -> Self {
        let m = G::Map::setup();

        let g: Vec<_> = (0..depth)
            .map(|i| {
                let mut h = Blake2b512::new();
                h.update(&(i as u32).to_be_bytes());
                point_of_random_bytes(&m, &h.finalize())
            })
            .collect();

        const MISC: usize = 1;
        let [h]: [G; MISC] = array::from_fn(|i| {
            let mut h = Blake2b512::new();
            h.update("srs_misc".as_bytes());
            h.update(&(i as u32).to_be_bytes());
            point_of_random_bytes(&m, &h.finalize())
        });

        SRS {
            g,
            h,
            lagrange_bases: HashMap::new(),
        }
    }
}
