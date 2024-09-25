use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use core::ops::AddAssign;
use groupmap::GroupMap;
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{cmp::min, collections::HashMap};

use crate::{
    commitment::{
        squeeze_challenge, squeeze_prechallenge, BatchEvaluationProof, BlindedCommitment,
        CommitmentCurve, EndoCurve, PolyComm,
    },
    error::CommitmentError,
    PolynomialsToCombine, SRS as SRSTrait,
};

#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq)]
#[serde(bound = "G: CanonicalDeserialize + CanonicalSerialize")]
pub struct SRS<G> {
    /// The vector of group elements for committing to polynomials in
    /// coefficient form.
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub g: Vec<G>,

    /// A group element used for blinding commitments
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub h: G,

    // TODO: the following field should be separated, as they are optimization
    // values
    /// Commitments to Lagrange bases, per domain size
    #[serde(skip)]
    pub lagrange_bases: HashMap<usize, Vec<PolyComm<G>>>,
}

impl<G> PartialEq for SRS<G>
where
    G: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.g == other.g && self.h == other.h
    }
}

pub fn endos<G: CommitmentCurve>() -> (G::BaseField, G::ScalarField)
where
    G::BaseField: PrimeField,
{
    let endo_q: G::BaseField = mina_poseidon::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r: G::ScalarField = mina_poseidon::sponge::endo_coefficient();
        let t = G::generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = G::of_coordinates(x * endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into_group() {
            potential_endo_r
        } else {
            potential_endo_r * potential_endo_r
        }
    };
    (endo_q, endo_r)
}

fn point_of_random_bytes<G: CommitmentCurve>(map: &G::Map, random_bytes: &[u8]) -> G
where
    G::BaseField: Field,
{
    // packing in bit-representation
    const N: usize = 31;
    let extension_degree = G::BaseField::extension_degree() as usize;

    let mut base_fields = Vec::with_capacity(N * extension_degree);

    for base_count in 0..extension_degree {
        let mut bits = [false; 8 * N];
        let offset = base_count * N;
        for i in 0..N {
            for j in 0..8 {
                bits[8 * i + j] = (random_bytes[offset + i] >> j) & 1 == 1;
            }
        }

        let n =
            <<G::BaseField as Field>::BasePrimeField as PrimeField>::BigInt::from_bits_be(&bits);
        let t = <<G::BaseField as Field>::BasePrimeField as PrimeField>::from_bigint(n)
            .expect("packing code has a bug");
        base_fields.push(t)
    }

    let t = G::BaseField::from_base_prime_field_elems(&base_fields).unwrap();

    let (x, y) = map.to_group(t);
    G::of_coordinates(x, y).mul_by_cofactor()
}

impl<G: CommitmentCurve> SRS<G> {
    /// This function creates SRS instance for circuits with number of rows up
    /// to `depth`.
    pub fn create(depth: usize) -> Self {
        let m = G::Map::setup();

        let g: Vec<_> = (0..depth)
            .map(|i| {
                let mut h = Blake2b512::new();
                h.update((i as u32).to_be_bytes());
                point_of_random_bytes(&m, &h.finalize())
            })
            .collect();

        // Compute a blinder
        let h = {
            let mut h = Blake2b512::new();
            h.update("srs_misc".as_bytes());
            // FIXME: This is for retrocompatibility with a previous version
            // that was using a list initialisation. It is not necessary.
            h.update(0_u32.to_be_bytes());
            point_of_random_bytes(&m, &h.finalize())
        };

        Self {
            g,
            h,
            lagrange_bases: HashMap::new(),
        }
    }

    pub fn max_degree(&self) -> usize {
        self.g.len()
    }

    /// Compute commitments to the lagrange basis corresponding to the given
    /// domain and cache them in the SRS
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
        // Consider the rows of M(w) * v. Let me write out the matrix and vector
        // so you can see more easily.
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
        // Therefore, the IFFT algorithm, when applied to the vector u (the
        // standard monomial basis) will yield the vector v of the (normalized)
        // Lagrange polynomials.
        //
        // Now, because the polynomial commitment scheme is additively
        // homomorphic, and because the commitment to the polynomial x^i is just
        // self.g[i], we can obtain commitments to the normalized Lagrange
        // polynomials by applying IFFT to the vector self.g[0..n].
        //
        //
        // Further still, we can do the same trick for 'chunked' polynomials.
        //
        // Recall that a chunked polynomial is some f of degree k*n - 1 with
        // f(x) = f_0(x) + x^n f_1(x) + ... + x^{(k-1) n} f_{k-1}(x)
        // where each f_i has degree n-1.
        //
        // In the above, if we set u = [ 1, x^2, ... x^{n-1}, 0, 0, .., 0 ]
        // then we effectively 'zero out' any polynomial terms higher than
        // x^{n-1}, leaving us with the 'partial Lagrange polynomials' that
        // contribute to f_0.
        //
        // Similarly, u = [ 0, 0, ..., 0, 1, x^2, ..., x^{n-1}, 0, 0, ..., 0]
        // with n leading zeros 'zeroes out' all terms except the 'partial
        // Lagrange polynomials' that contribute to f_1, and likewise for each
        // f_i.
        //
        // By computing each of these, and recollecting the terms as a vector of
        // polynomial commitments, we obtain a chunked commitment to the L_i
        // polynomials.
        let srs_size = self.g.len();
        let num_elems = (n + srs_size - 1) / srs_size;
        let mut elems = Vec::with_capacity(num_elems);

        // For each chunk
        for i in 0..num_elems {
            // Initialize the vector with zero curve points
            let mut lg: Vec<<G as AffineRepr>::Group> = vec![<G as AffineRepr>::Group::zero(); n];
            // Overwrite the terms corresponding to that chunk with the SRS curve points
            let start_offset = i * srs_size;
            let num_terms = min((i + 1) * srs_size, n) - start_offset;
            for j in 0..num_terms {
                lg[start_offset + j] = self.g[j].into_group()
            }
            // Apply the IFFT
            domain.ifft_in_place(&mut lg);
            // Append the 'partial Langrange polynomials' to the vector of elems chunks
            elems.push(<G as AffineRepr>::Group::normalize_batch(lg.as_mut_slice()));
        }

        let chunked_commitments: Vec<_> = (0..n)
            .map(|i| PolyComm {
                elems: elems.iter().map(|v| v[i]).collect(),
            })
            .collect();
        self.lagrange_bases.insert(n, chunked_commitments);
    }

    /// This function creates a trusted-setup SRS instance for circuits with
    /// number of rows up to `depth`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it creates a trusted setup and the toxic
    /// waste is passed as a parameter.
    pub unsafe fn create_trusted_setup(x: G::ScalarField, depth: usize) -> Self {
        let m = G::Map::setup();

        let mut x_pow = G::ScalarField::one();
        let g: Vec<_> = (0..depth)
            .map(|_| {
                let res = G::generator().mul(x_pow);
                x_pow *= x;
                res.into_affine()
            })
            .collect();

        // Compute a blinder
        let h = {
            let mut h = Blake2b512::new();
            h.update("srs_misc".as_bytes());
            // FIXME: This is for retrocompatibility with a previous version
            // that was using a list initialisation. It is not necessary.
            h.update(0_u32.to_be_bytes());
            point_of_random_bytes(&m, &h.finalize())
        };

        Self {
            g,
            h,
            lagrange_bases: HashMap::new(),
        }
    }
}

impl<G> SRSTrait<G> for SRS<G>
where
    G: CommitmentCurve,
{
    /// The maximum polynomial degree that can be committed to
    fn max_poly_size(&self) -> usize {
        self.g.len()
    }

    fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>> {
        self.lagrange_bases.get(&domain_size)
    }

    fn blinding_commitment(&self) -> G {
        self.h
    }

    /// Turns a non-hiding polynomial commitment into a hidding polynomial
    /// commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with
    /// a random `w` per commitment.
    fn mask(
        &self,
        comm: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        let blinders = comm.map(|_| G::ScalarField::rand(rng));
        self.mask_custom(comm, &blinders).unwrap()
    }

    /// Same as [SRS::mask] except that you can pass the blinders manually.
    fn mask_custom(
        &self,
        com: PolyComm<G>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError> {
        let commitment = com
            .zip(blinders)
            .ok_or_else(|| CommitmentError::BlindersDontMatch(blinders.len(), com.len()))?
            .map(|(g, b)| {
                let mut g_masked = self.h.mul(b);
                g_masked.add_assign(&g);
                g_masked.into_affine()
            });
        Ok(BlindedCommitment {
            commitment,
            blinders: blinders.clone(),
        })
    }

    /// This function commits a polynomial using the SRS' basis of size `n`.
    /// - `plnm`: polynomial to commit to with max size of sections
    /// - `num_chunks`: the number of commitments to be included in the output polynomial commitment
    /// The function returns an unbounded commitment vector
    /// (which splits the commitment into several commitments of size at most `n`).
    fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
    ) -> PolyComm<G> {
        let is_zero = plnm.is_zero();

        let coeffs: Vec<_> = plnm.iter().map(|c| c.into_bigint()).collect();

        // chunk while commiting
        let mut elems = vec![];
        if is_zero {
            elems.push(G::zero());
        } else {
            coeffs.chunks(self.g.len()).for_each(|coeffs_chunk| {
                let chunk = G::Group::msm_bigint(&self.g, coeffs_chunk);
                elems.push(chunk.into_affine());
            });
        }

        for _ in elems.len()..num_chunks {
            elems.push(G::zero());
        }

        PolyComm::<G> { elems }
    }

    /// Commits a polynomial, potentially splitting the result in multiple
    /// commitments.
    fn commit(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.mask(self.commit_non_hiding(plnm, num_chunks), rng)
    }

    fn commit_custom(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError> {
        self.mask_custom(self.commit_non_hiding(plnm, num_chunks), blinders)
    }

    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G> {
        let basis = self
            .lagrange_bases
            .get(&domain.size())
            .unwrap_or_else(|| panic!("lagrange bases for size {} not found", domain.size()));
        let commit_evaluations = |evals: &Vec<G::ScalarField>, basis: &Vec<PolyComm<G>>| {
            PolyComm::<G>::multi_scalar_mul(&basis.iter().collect::<Vec<_>>()[..], &evals[..])
        };
        match domain.size.cmp(&plnm.domain().size) {
            std::cmp::Ordering::Less => {
                let s = (plnm.domain().size / domain.size) as usize;
                let v: Vec<_> = (0..(domain.size())).map(|i| plnm.evals[s * i]).collect();
                commit_evaluations(&v, basis)
            }
            std::cmp::Ordering::Equal => commit_evaluations(&plnm.evals, basis),
            std::cmp::Ordering::Greater => {
                panic!("desired commitment domain size ({}) greater than evaluations' domain size ({}):", domain.size, plnm.domain().size)
            }
        }
    }

    fn commit_evaluations(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.mask(self.commit_evaluations_non_hiding(domain, plnm), rng)
    }

    fn commit_evaluations_custom(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError> {
        self.mask_custom(self.commit_evaluations_non_hiding(domain, plnm), blinders)
    }

    fn create(depth: usize) -> Self {
        SRS::create(depth)
    }

    fn add_lagrange_basis(&mut self, domain: D<<G>::ScalarField>) {
        self.add_lagrange_basis(domain)
    }

    fn size(&self) -> usize {
        self.g.len()
    }
}

/// Additional methods on the SRS structure
impl<G: CommitmentCurve> SRS<G>
where
    <G as CommitmentCurve>::Map: Sync,
    G::BaseField: PrimeField,
{
    /// This function creates SRS instance for circuits with number of rows up
    /// to `depth`.
    pub fn create_parallel(depth: usize) -> Self {
        let m = G::Map::setup();

        let g: Vec<_> = (0..depth)
            .into_par_iter()
            .map(|i| {
                let mut h = Blake2b512::new();
                h.update((i as u32).to_be_bytes());
                point_of_random_bytes(&m, &h.finalize())
            })
            .collect();

        // Compute a blinder
        let h = {
            let mut h = Blake2b512::new();
            h.update("srs_misc".as_bytes());
            // FIXME: This is for retrocompatibility with a previous version
            // that was using a list initialisation. It is not necessary.
            h.update(0_u32.to_be_bytes());
            point_of_random_bytes(&m, &h.finalize())
        };

        Self {
            g,
            h,
            lagrange_bases: HashMap::new(),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct OpeningProof<G: AffineRepr> {
    /// Vector of rounds of L & R commitments
    #[serde_as(as = "Vec<(o1_utils::serialization::SerdeAs, o1_utils::serialization::SerdeAs)>")]
    pub lr: Vec<(G, G)>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub delta: G,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z1: G::ScalarField,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z2: G::ScalarField,
    /// A final folded commitment base
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub sg: G,
}

impl<BaseField: PrimeField, G: AffineRepr<BaseField = BaseField> + CommitmentCurve + EndoCurve>
    crate::OpenProof<G> for OpeningProof<G>
{
    type SRS = SRS<G>;

    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineRepr>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[<G as AffineRepr>::ScalarField], // vector of evaluation points
        polyscale: <G as AffineRepr>::ScalarField, // scaling factor for polynoms
        evalscale: <G as AffineRepr>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                      // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge:
            Clone + FqSponge<<G as AffineRepr>::BaseField, G, <G as AffineRepr>::ScalarField>,
        RNG: RngCore + CryptoRng,
    {
        srs.open(group_map, plnms, elm, polyscale, evalscale, sponge, rng)
    }

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<<G as AffineRepr>::BaseField, G, <G as AffineRepr>::ScalarField>,
        RNG: RngCore + CryptoRng,
    {
        srs.verify(group_map, batch, rng)
    }
}

/// Commitment round challenges (endo mapped) and their inverses.
pub struct Challenges<F> {
    pub chal: Vec<F>,
    pub chal_inv: Vec<F>,
}

impl<G: AffineRepr> OpeningProof<G> {
    /// Computes a log-sized vector of scalar challenges for
    /// recombining elements inside the IPA.
    pub fn prechallenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        sponge: &mut EFqSponge,
    ) -> Vec<ScalarChallenge<G::ScalarField>> {
        let _t = sponge.challenge_fq();
        self.lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_prechallenge(sponge)
            })
            .collect()
    }

    /// Same as `prechallenges`, but maps scalar challenges using the
    /// provided endomorphism, and computes their inverses.
    pub fn challenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        endo_r: &G::ScalarField,
        sponge: &mut EFqSponge,
    ) -> Challenges<G::ScalarField> {
        let chal: Vec<_> = self
            .lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_challenge(endo_r, sponge)
            })
            .collect();

        let chal_inv = {
            let mut cs = chal.clone();
            ark_ff::batch_inversion(&mut cs);
            cs
        };

        Challenges { chal, chal_inv }
    }
}
