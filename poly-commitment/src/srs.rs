//! This module implements the Marlin structured reference string primitive

use crate::commitment::CommitmentCurve;
pub use crate::{CommitmentField, QnrField};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use array_init::array_init;
use blake2::{Blake2b512, Digest};
use groupmap::GroupMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
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
    pub lagrange_bases: HashMap<usize, Vec<G>>,
    /// Coefficient for the curve endomorphism
    #[serde(skip)]
    pub endo_r: G::ScalarField,
    /// Coefficient for the curve endomorphism
    #[serde(skip)]
    pub endo_q: G::BaseField,
}

pub fn endos<G: CommitmentCurve>() -> (G::BaseField, G::ScalarField)
where
    G::BaseField: PrimeField,
{
    let endo_q: G::BaseField = oracle::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r: G::ScalarField = oracle::sponge::endo_coefficient();
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
    G::ScalarField: CommitmentField,
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
    G::ScalarField: CommitmentField,
{
    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    /// Compute commitments to the lagrange basis corresponding to the given domain and
    /// cache them in the SRS
    pub fn add_lagrange_basis(&mut self, domain: D<G::ScalarField>) {
        let n = domain.size();
        if n > self.g.len() {
            panic!(
                "add_lagrange_basis: Domain size {} larger than SRS size {}",
                n,
                self.g.len()
            );
        }

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
        let mut lg: Vec<<G as AffineCurve>::Projective> =
            self.g[0..n].iter().map(|g| g.into_projective()).collect();
        domain.ifft_in_place(&mut lg);

        <G as AffineCurve>::Projective::batch_normalization(lg.as_mut_slice());
        self.lagrange_bases
            .insert(n, lg.iter().map(|g| g.into_affine()).collect());
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

        let (endo_q, endo_r) = endos::<G>();

        const MISC: usize = 1;
        let [h]: [G; MISC] = array_init(|i| {
            let mut h = Blake2b512::new();
            h.update("srs_misc".as_bytes());
            h.update(&(i as u32).to_be_bytes());
            point_of_random_bytes(&m, &h.finalize())
        });

        SRS {
            g,
            h,
            lagrange_bases: HashMap::new(),
            endo_r,
            endo_q,
        }
    }
}
