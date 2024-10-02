//! This module contains the implementation of the polynomial commitment scheme
//! called the Inner Product Argument (IPA) as described in [Efficient
//! Zero-Knowledge Arguments for Arithmetic Circuits in the Discrete Log
//! Setting](https://eprint.iacr.org/2016/263)

use crate::{
    commitment::{
        b_poly, b_poly_coefficients, combine_commitments, shift_scalar, BatchEvaluationProof,
        CommitmentCurve, *,
    },
    error::CommitmentError,
    BlindedCommitment, PolyComm, PolynomialsToCombine, SRS as SRSTrait,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    Radix2EvaluationDomain as D,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use groupmap::GroupMap;
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::{
    field_helpers::{inner_prod, pows},
    math, ExtendedDensePolynomial,
};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{cmp::min, collections::HashMap, iter::Iterator, ops::AddAssign};

/// A formal sum of the form
/// `s_0 * p_0 + ... s_n * p_n`
/// where each `s_i` is a scalar and each `p_i` is a polynomial.
/// The parameter `P` is expected to be the coefficients of the polynomial
/// `p_i`, even though we could treat it as the evaluations.
///
/// This hypothesis is important if `to_dense_polynomial` is called.
#[derive(Default)]
struct ScaledChunkedPolynomial<F, P>(Vec<(F, P)>);

/// Represent a polynomial either with its coefficients or its evaluations
pub enum DensePolynomialOrEvaluations<'a, F: FftField, D: EvaluationDomain<F>> {
    /// Polynomial represented by its coefficients
    DensePolynomial(&'a DensePolynomial<F>),
    /// Polynomial represented by its evaluations over a domain D
    Evaluations(&'a Evaluations<F, D>, D),
}

impl<F, P> ScaledChunkedPolynomial<F, P> {
    fn add_poly(&mut self, scale: F, p: P) {
        self.0.push((scale, p))
    }
}

impl<'a, F: Field> ScaledChunkedPolynomial<F, &'a [F]> {
    /// Compute the resulting scaled polynomial.
    /// Example:
    /// Given the two polynomials `1 + 2X` and `3 + 4X`, and the scaling
    /// factors `2` and `3`, the result is the polynomial `11 + 16X`.
    /// ```text
    /// 2 * [1, 2] + 3 * [3, 4] = [2, 4] + [9, 12] = [11, 16]
    /// ```
    fn to_dense_polynomial(&self) -> DensePolynomial<F> {
        // Note: using a reference to avoid reallocation of the result.
        let mut res = DensePolynomial::<F>::zero();

        let scaled: Vec<_> = self
            .0
            .par_iter()
            .map(|(scale, segment)| {
                let scale = *scale;
                // We simply scale each coefficients.
                // It is simply because DensePolynomial doesn't have a method
                // `scale`.
                let v = segment.par_iter().map(|x| scale * *x).collect();
                DensePolynomial::from_coefficients_vec(v)
            })
            .collect();

        for p in scaled {
            res += &p;
        }

        res
    }
}

/// Combine the polynomials using a scalar (`polyscale`), creating a single
/// unified polynomial to open. This function also accepts polynomials in
/// evaluations form. In this case it applies an IFFT, and, if necessarry,
/// applies chunking to it (ie. split it in multiple polynomials of
/// degree less than the SRS size).
/// Parameters:
/// - plnms: vector of polynomials, either in evaluations or coefficients form.
/// The order of the output follows the order of this structure.
/// - polyscale: scalar to combine the polynomials, which will be scaled based
/// on the number of polynomials to combine.
///
/// Example:
/// Given the three polynomials `p1(X)`, and `p3(X)` in coefficients
/// forms, p2(X) in evaluation form,
/// and the scaling factor `s`, the result will be the polynomial:
///
/// ```text
/// p1(X) + s * i_fft(chunks(p2))(X) + s^2 p3(X)
/// ```
///
/// Additional complexity is added to handle chunks.
// TODO: move into utils? It is useful for multiple PCS
pub fn combine_polys<G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>>(
    plnms: PolynomialsToCombine<G, D>,
    polyscale: G::ScalarField,
    srs_length: usize,
) -> (DensePolynomial<G::ScalarField>, G::ScalarField) {
    // Initialising the output for the combined coefficients forms
    let mut plnm_coefficients =
        ScaledChunkedPolynomial::<G::ScalarField, &[G::ScalarField]>::default();
    // Initialising the output for the combined evaluations forms
    let mut plnm_evals_part = {
        // For now just check that all the evaluation polynomials are the same
        // degree so that we can do just a single FFT.
        // If/when we change this, we can add more complicated code to handle
        // different degrees.
        let degree = plnms
            .iter()
            .fold(None, |acc, (p, _)| match p {
                DensePolynomialOrEvaluations::DensePolynomial(_) => acc,
                DensePolynomialOrEvaluations::Evaluations(_, d) => {
                    if let Some(n) = acc {
                        assert_eq!(n, d.size());
                    }
                    Some(d.size())
                }
            })
            .unwrap_or(0);
        vec![G::ScalarField::zero(); degree]
    };

    let mut omega = G::ScalarField::zero();
    let mut scale = G::ScalarField::one();

    // Iterating over polynomials in the batch.
    // Note that `omegas` are given as `PolyComm<G::ScalarField>`. They are
    // evaluations.
    // We do modify two different structures depending on the form of the
    // polynomial we are currently processing: `plnm` and `plnm_evals_part`.
    // We do need to treat both forms separately.
    for (p_i, omegas) in plnms {
        match p_i {
            // Here we scale the polynomial in evaluations forms
            // Note that based on the check above, sub_domain.size() always give
            // the same value
            DensePolynomialOrEvaluations::Evaluations(evals_i, sub_domain) => {
                let stride = evals_i.evals.len() / sub_domain.size();
                let evals = &evals_i.evals;
                plnm_evals_part
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, x)| {
                        *x += scale * evals[i * stride];
                    });
                for j in 0..omegas.elems.len() {
                    omega += &(omegas.elems[j] * scale);
                    scale *= &polyscale;
                }
            }

            // Here we scale the polynomial in coefficient forms
            DensePolynomialOrEvaluations::DensePolynomial(p_i) => {
                let mut offset = 0;
                // iterating over chunks of the polynomial
                for j in 0..omegas.elems.len() {
                    let segment = &p_i.coeffs[std::cmp::min(offset, p_i.coeffs.len())
                        ..std::cmp::min(offset + srs_length, p_i.coeffs.len())];
                    plnm_coefficients.add_poly(scale, segment);

                    omega += &(omegas.elems[j] * scale);
                    scale *= &polyscale;
                    offset += srs_length;
                }
            }
        }
    }

    // Now, we will combine both evaluations and coefficients forms

    // plnm will be our final combined polynomial. We first treat the
    // polynomials in coefficients forms, which is simply scaling the
    // coefficients and add them.
    let mut plnm = plnm_coefficients.to_dense_polynomial();

    if !plnm_evals_part.is_empty() {
        // n is the number of evaluations points, which is a multiple of the
        // domain size.
        // We treat now each chunk.
        let n = plnm_evals_part.len();
        let max_poly_size = srs_length;
        // equiv to divceil, but unstable in rust < 1.73.
        let num_chunks = n / max_poly_size + if n % max_poly_size == 0 { 0 } else { 1 };
        // Interpolation on the whole domain, i.e. it can be d2, d4, etc.
        plnm += &Evaluations::from_vec_and_domain(plnm_evals_part, D::new(n).unwrap())
            .interpolate()
            .to_chunked_polynomial(num_chunks, max_poly_size)
            .linearize(polyscale);
    }

    (plnm, omega)
}

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

/// Additional methods for the SRS structure
impl<G: CommitmentCurve> SRS<G> {
    /// This function verifies a batch of polynomial commitment opening proofs.
    /// Return `true` if the verification is successful, `false` otherwise.
    pub fn verify<EFqSponge, RNG>(
        &self,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, OpeningProof<G>>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
        RNG: RngCore + CryptoRng,
        G::BaseField: PrimeField,
    {
        // Verifier checks for all i,
        // c_i Q_i + delta_i = z1_i (G_i + b_i U_i) + z2_i H
        //
        // if we sample evalscale at random, it suffices to check
        //
        // 0 == sum_i evalscale^i (c_i Q_i + delta_i - ( z1_i (G_i + b_i U_i) + z2_i H ))
        //
        // and because each G_i is a multiexp on the same array self.g, we
        // can batch the multiexp across proofs.
        //
        // So for each proof in the batch, we add onto our big multiexp the following terms
        // evalscale^i c_i Q_i
        // evalscale^i delta_i
        // - (evalscale^i z1_i) G_i
        // - (evalscale^i z2_i) H
        // - (evalscale^i z1_i b_i) U_i

        // We also check that the sg component of the proof is equal to the polynomial commitment
        // to the "s" array

        let nonzero_length = self.g.len();

        let max_rounds = math::ceil_log2(nonzero_length);

        let padded_length = 1 << max_rounds;

        let (_, endo_r) = endos::<G>();

        // TODO: This will need adjusting
        let padding = padded_length - nonzero_length;
        let mut points = vec![self.h];
        points.extend(self.g.clone());
        points.extend(vec![G::zero(); padding]);

        let mut scalars = vec![G::ScalarField::zero(); padded_length + 1];
        assert_eq!(scalars.len(), points.len());

        // sample randomiser to scale the proofs with
        let rand_base = G::ScalarField::rand(rng);
        let sg_rand_base = G::ScalarField::rand(rng);

        let mut rand_base_i = G::ScalarField::one();
        let mut sg_rand_base_i = G::ScalarField::one();

        for BatchEvaluationProof {
            sponge,
            evaluation_points,
            polyscale,
            evalscale,
            evaluations,
            opening,
            combined_inner_product,
        } in batch.iter_mut()
        {
            sponge.absorb_fr(&[shift_scalar::<G>(*combined_inner_product)]);

            let t = sponge.challenge_fq();
            let u: G = {
                let (x, y) = group_map.to_group(t);
                G::of_coordinates(x, y)
            };

            let Challenges { chal, chal_inv } = opening.challenges::<EFqSponge>(&endo_r, sponge);

            sponge.absorb_g(&[opening.delta]);
            let c = ScalarChallenge(sponge.challenge()).to_field(&endo_r);

            // < s, sum_i evalscale^i pows(evaluation_point[i]) >
            // ==
            // sum_i evalscale^i < s, pows(evaluation_point[i]) >
            let b0 = {
                let mut scale = G::ScalarField::one();
                let mut res = G::ScalarField::zero();
                for &e in evaluation_points.iter() {
                    let term = b_poly(&chal, e);
                    res += &(scale * term);
                    scale *= *evalscale;
                }
                res
            };

            let s = b_poly_coefficients(&chal);

            let neg_rand_base_i = -rand_base_i;

            // TERM
            // - rand_base_i z1 G
            //
            // we also add -sg_rand_base_i * G to check correctness of sg.
            points.push(opening.sg);
            scalars.push(neg_rand_base_i * opening.z1 - sg_rand_base_i);

            // Here we add
            // sg_rand_base_i * ( < s, self.g > )
            // =
            // < sg_rand_base_i s, self.g >
            //
            // to check correctness of the sg component.
            {
                let terms: Vec<_> = s.par_iter().map(|s| sg_rand_base_i * s).collect();

                for (i, term) in terms.iter().enumerate() {
                    scalars[i + 1] += term;
                }
            }

            // TERM
            // - rand_base_i * z2 * H
            scalars[0] -= &(rand_base_i * opening.z2);

            // TERM
            // -rand_base_i * (z1 * b0 * U)
            scalars.push(neg_rand_base_i * (opening.z1 * b0));
            points.push(u);

            // TERM
            // rand_base_i c_i Q_i
            // = rand_base_i c_i
            //   (sum_j (chal_invs[j] L_j + chals[j] R_j) + P_prime)
            // where P_prime = combined commitment + combined_inner_product * U
            let rand_base_i_c_i = c * rand_base_i;
            for ((l, r), (u_inv, u)) in opening.lr.iter().zip(chal_inv.iter().zip(chal.iter())) {
                points.push(*l);
                scalars.push(rand_base_i_c_i * u_inv);

                points.push(*r);
                scalars.push(rand_base_i_c_i * u);
            }

            // TERM
            // sum_j evalscale^j (sum_i polyscale^i f_i) (elm_j)
            // == sum_j sum_i evalscale^j polyscale^i f_i(elm_j)
            // == sum_i polyscale^i sum_j evalscale^j f_i(elm_j)
            combine_commitments(
                evaluations,
                &mut scalars,
                &mut points,
                *polyscale,
                rand_base_i_c_i,
            );

            scalars.push(rand_base_i_c_i * *combined_inner_product);
            points.push(u);

            scalars.push(rand_base_i);
            points.push(opening.delta);

            rand_base_i *= &rand_base;
            sg_rand_base_i *= &sg_rand_base;
        }

        // verify the equation
        let scalars: Vec<_> = scalars.iter().map(|x| x.into_bigint()).collect();
        G::Group::msm_bigint(&points, &scalars) == G::Group::zero()
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

    fn add_lagrange_basis(&mut self, domain: D<<G>::ScalarField>) {
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

    fn size(&self) -> usize {
        self.g.len()
    }
}

impl<G: CommitmentCurve> SRS<G> {
    /// This function opens polynomials in batch at several points
    /// - plnms: batch of polynomials to open commitments for
    /// - elm: evaluation point vector to open the commitments at
    /// - polyscale: used to combine polynomials for opening commitments in batch
    /// (we will open the \sum_i polyscale^i * plnms.(i))
    /// - evalscale: used to combine evaluations to open on only one point
    /// - sponge: parameters for the random oracle argument
    /// - rng: used for blinders for the zk property
    /// A slight modification to the original protocol is done
    /// when absorbing the first prover message.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::many_single_char_names)]
    pub fn open<EFqSponge, RNG, D: EvaluationDomain<G::ScalarField>>(
        &self,
        group_map: &G::Map,
        // TODO(mimoo): create a type for that entry
        plnms: PolynomialsToCombine<G, D>,
        elm: &[G::ScalarField],
        polyscale: G::ScalarField,
        evalscale: G::ScalarField,
        mut sponge: EFqSponge,
        rng: &mut RNG,
    ) -> OpeningProof<G>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        RNG: RngCore + CryptoRng,
        G::BaseField: PrimeField,
        G: EndoCurve,
    {
        let (endo_q, endo_r) = endos::<G>();

        let rounds = math::ceil_log2(self.g.len());
        let padded_length = 1 << rounds;

        // TODO: Trim this to the degree of the largest polynomial
        // TODO: We do always suppose we have a power of 2 for the SRS in
        // practice. Therefore, padding equals zero, and this code can be
        // removed. Only a current test case uses a SRS with a non-power of 2.
        let padding = padded_length - self.g.len();
        let mut g = self.g.clone();
        g.extend(vec![G::zero(); padding]);

        let (p, blinding_factor) = combine_polys::<G, D>(plnms, polyscale, self.g.len());

        // The initial evaluation vector for polynomial commitment b_init is not
        // just the powers of a single point as in the original IPA, but rather
        // a vector of linearly combined powers with `evalscale` as recombiner.
        //
        // b_init[j] = Σ_i evalscale^i elm_i^j
        //          = ζ^j + evalscale * ζ^j ω^j (in the specific case of opening)
        let b_init = {
            // randomise/scale the eval powers
            let mut scale = G::ScalarField::one();
            let mut res: Vec<G::ScalarField> =
                (0..padded_length).map(|_| G::ScalarField::zero()).collect();
            for e in elm {
                for (i, t) in pows(padded_length, *e).iter().enumerate() {
                    res[i] += &(scale * t);
                }
                scale *= &evalscale;
            }
            res
        };

        // Combined polynomial p, evaluated at the combined point b_init.
        let combined_inner_product = p
            .coeffs
            .iter()
            .zip(b_init.iter())
            .map(|(a, b)| *a * b)
            .fold(G::ScalarField::zero(), |acc, x| acc + x);

        // Usually, the prover sends `combined_inner_product`` to the verifier
        // So we should absorb `combined_inner_product``
        // However it is more efficient in the recursion circuit
        // to absorb a slightly modified version of it.
        // As a reminder, in a recursive seeting, the challenges are given as a public input
        // and verified in the next iteration.
        // See the `shift_scalar`` doc.
        sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product)]);

        let t = sponge.challenge_fq();
        let u: G = {
            let (x, y) = group_map.to_group(t);
            G::of_coordinates(x, y)
        };

        let mut a = p.coeffs;
        assert!(padded_length >= a.len());
        a.extend(vec![G::ScalarField::zero(); padded_length - a.len()]);

        let mut b = b_init;

        let mut lr = vec![];

        let mut blinders = vec![];

        let mut chals = vec![];
        let mut chal_invs = vec![];

        // The main IPA folding loop that has log iterations.
        for _ in 0..rounds {
            let n = g.len() / 2;
            // Pedersen bases
            let (g_lo, g_hi) = (&g[0..n], &g[n..]);
            // Polynomial coefficients
            let (a_lo, a_hi) = (&a[0..n], &a[n..]);
            // Evaluation points
            let (b_lo, b_hi) = (&b[0..n], &b[n..]);

            // Blinders for L/R
            let rand_l = <G::ScalarField as UniformRand>::rand(rng);
            let rand_r = <G::ScalarField as UniformRand>::rand(rng);

            // Pedersen commitment to a_lo,rand_l,<a_hi,b_lo>
            let l = G::Group::msm_bigint(
                &[g_lo, &[self.h, u]].concat(),
                &[a_hi, &[rand_l, inner_prod(a_hi, b_lo)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_bigint())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            let r = G::Group::msm_bigint(
                &[g_hi, &[self.h, u]].concat(),
                &[a_lo, &[rand_r, inner_prod(a_lo, b_hi)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_bigint())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            lr.push((l, r));
            blinders.push((rand_l, rand_r));

            sponge.absorb_g(&[l]);
            sponge.absorb_g(&[r]);

            // Round #i challenges
            let u_pre = squeeze_prechallenge(&mut sponge);
            let u = u_pre.to_field(&endo_r);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

            // IPA-folding polynomial coefficients
            a = a_hi
                .par_iter()
                .zip(a_lo)
                .map(|(&hi, &lo)| {
                    // lo + u_inv * hi
                    let mut res = hi;
                    res *= u_inv;
                    res += &lo;
                    res
                })
                .collect();

            // IPA-folding evaluation points
            b = b_lo
                .par_iter()
                .zip(b_hi)
                .map(|(&lo, &hi)| {
                    // lo + u * hi
                    let mut res = hi;
                    res *= u;
                    res += &lo;
                    res
                })
                .collect();

            // IPA-folding bases
            g = G::combine_one_endo(endo_r, endo_q, g_lo, g_hi, u_pre);
        }

        assert!(
            g.len() == 1 && a.len() == 1 && b.len() == 1,
            "IPA commitment folding must produce single elements after log rounds"
        );
        let a0 = a[0];
        let b0 = b[0];
        let g0 = g[0];

        // Schnorr/Sigma-protocol part

        // r_prime = blinding_factor + \sum_i (rand_l[i] * (u[i]^{-1}) + rand_r * u[i])
        //   where u is a vector of folding challenges, and rand_l/rand_r are
        //   intermediate L/R blinders
        let r_prime = blinders
            .iter()
            .zip(chals.iter().zip(chal_invs.iter()))
            .map(|((rand_l, rand_r), (u, u_inv))| ((*rand_l) * u_inv) + (*rand_r * u))
            .fold(blinding_factor, |acc, x| acc + x);

        let d = <G::ScalarField as UniformRand>::rand(rng);
        let r_delta = <G::ScalarField as UniformRand>::rand(rng);

        // delta = (g0 + u*b0)*d + h*r_delta
        let delta = ((g0.into_group() + (u.mul(b0))).into_affine().mul(d) + self.h.mul(r_delta))
            .into_affine();

        sponge.absorb_g(&[delta]);
        let c = ScalarChallenge(sponge.challenge()).to_field(&endo_r);

        let z1 = a0 * c + d;
        let z2 = r_prime * c + r_delta;

        OpeningProof {
            delta,
            lr,
            z1,
            z2,
            sg: g0,
        }
    }

    /// This function is a debugging helper.
    pub fn prover_polynomials_to_verifier_evaluations<D: EvaluationDomain<G::ScalarField>>(
        &self,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[G::ScalarField], // vector of evaluation points
    ) -> Vec<Evaluation<G>>
    where
        G::BaseField: PrimeField,
    {
        plnms
            .iter()
            .enumerate()
            .map(|(i, (poly_or_evals, blinders))| {
                let poly = match poly_or_evals {
                    DensePolynomialOrEvaluations::DensePolynomial(poly) => (*poly).clone(),
                    DensePolynomialOrEvaluations::Evaluations(evals, _) => {
                        (*evals).clone().interpolate()
                    }
                };
                let chunked_polynomial =
                    poly.to_chunked_polynomial(blinders.elems.len(), self.g.len());
                let chunked_commitment = { self.commit_non_hiding(&poly, blinders.elems.len()) };
                let masked_commitment = match self.mask_custom(chunked_commitment, blinders) {
                    Ok(comm) => comm,
                    Err(err) => panic!("Error at index {i}: {err}"),
                };
                let chunked_evals = elm
                    .iter()
                    .map(|elm| chunked_polynomial.evaluate_chunks(*elm))
                    .collect();
                Evaluation {
                    commitment: masked_commitment.commitment,

                    evaluations: chunked_evals,
                }
            })
            .collect()
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

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::OpeningProof;
    use ark_ec::AffineRepr;
    use ocaml;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlOpeningProof<G, F> {
        /// vector of rounds of L & R commitments
        pub lr: Vec<(G, G)>,
        pub delta: G,
        pub z1: F,
        pub z2: F,
        pub sg: G,
    }

    impl<G, CamlF, CamlG> From<OpeningProof<G>> for CamlOpeningProof<CamlG, CamlF>
    where
        G: AffineRepr,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(opening_proof: OpeningProof<G>) -> Self {
            Self {
                lr: opening_proof
                    .lr
                    .into_iter()
                    .map(|(g1, g2)| (CamlG::from(g1), CamlG::from(g2)))
                    .collect(),
                delta: CamlG::from(opening_proof.delta),
                z1: opening_proof.z1.into(),
                z2: opening_proof.z2.into(),
                sg: CamlG::from(opening_proof.sg),
            }
        }
    }

    impl<G, CamlF, CamlG> From<CamlOpeningProof<CamlG, CamlF>> for OpeningProof<G>
    where
        G: AffineRepr,
        CamlG: Into<G>,
        CamlF: Into<G::ScalarField>,
    {
        fn from(caml: CamlOpeningProof<CamlG, CamlF>) -> Self {
            Self {
                lr: caml
                    .lr
                    .into_iter()
                    .map(|(g1, g2)| (g1.into(), g2.into()))
                    .collect(),
                delta: caml.delta.into(),
                z1: caml.z1.into(),
                z2: caml.z2.into(),
                sg: caml.sg.into(),
            }
        }
    }
}
