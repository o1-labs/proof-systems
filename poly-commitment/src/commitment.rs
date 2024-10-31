//! This module implements Dlog-based polynomial commitment schema.
//! The folowing functionality is implemented
//!
//! 1. Commit to polynomial with its max degree
//! 2. Open polynomial commitment batch at the given evaluation point and scaling factor scalar
//!     producing the batched opening proof
//! 3. Verify batch of batched opening proofs

use crate::{
    error::CommitmentError,
    srs::{endos, SRS},
    SRS as SRSTrait,
};
use ark_ec::{
    models::short_weierstrass::Affine as SWJAffine, short_weierstrass::SWCurveConfig, AffineRepr,
    CurveGroup, VariableBaseMSM,
};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::ops::{Add, AddAssign, Sub};
use groupmap::{BWParameters, GroupMap};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::{math, ExtendedDensePolynomial as _};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::iter::Iterator;

use super::evaluation_proof::*;

/// A polynomial commitment.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "C: CanonicalDeserialize + CanonicalSerialize")]
pub struct PolyComm<C> {
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub elems: Vec<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedCommitment<G>
where
    G: CommitmentCurve,
{
    pub commitment: PolyComm<G>,
    pub blinders: PolyComm<G::ScalarField>,
}

impl<T> PolyComm<T> {
    pub fn new(elems: Vec<T>) -> Self {
        Self { elems }
    }
}

impl<A: Clone> PolyComm<A>
where
    A: CanonicalDeserialize + CanonicalSerialize,
{
    pub fn map<B, F>(&self, mut f: F) -> PolyComm<B>
    where
        F: FnMut(A) -> B,
        B: CanonicalDeserialize + CanonicalSerialize,
    {
        let elems = self.elems.iter().map(|x| f(x.clone())).collect();
        PolyComm { elems }
    }

    /// Returns the length of the commitment.
    pub fn len(&self) -> usize {
        self.elems.len()
    }

    /// Returns `true` if the commitment is empty.
    pub fn is_empty(&self) -> bool {
        self.elems.is_empty()
    }
}

impl<A: Copy + CanonicalDeserialize + CanonicalSerialize> PolyComm<A> {
    // TODO: if all callers end up calling unwrap, just call this zip_eq and panic here (and document the panic)
    pub fn zip<B: Copy + CanonicalDeserialize + CanonicalSerialize>(
        &self,
        other: &PolyComm<B>,
    ) -> Option<PolyComm<(A, B)>> {
        if self.elems.len() != other.elems.len() {
            return None;
        }
        let elems = self
            .elems
            .iter()
            .zip(other.elems.iter())
            .map(|(x, y)| (*x, *y))
            .collect();
        Some(PolyComm { elems })
    }
}

/// Inside the circuit, we have a specialized scalar multiplication which computes
/// either
///
/// ```ignore
/// |g: G, x: G::ScalarField| g.scale(x + 2^n)
/// ```
///
/// if the scalar field of G is greater than the size of the base field
/// and
///
/// ```ignore
/// |g: G, x: G::ScalarField| g.scale(2*x + 2^n)
/// ```
///
/// otherwise. So, if we want to actually scale by `s`, we need to apply the inverse function
/// of `|x| x + 2^n` (or of `|x| 2*x + 2^n` in the other case), before supplying the scalar
/// to our in-circuit scalar-multiplication function. This computes that inverse function.
/// Namely,
///
/// ```ignore
/// |x: G::ScalarField| x - 2^n
/// ```
///
/// when the scalar field is larger than the base field and
///
/// ```ignore
/// |x: G::ScalarField| (x - 2^n) / 2
/// ```
///
/// in the other case.
pub fn shift_scalar<G: AffineRepr>(x: G::ScalarField) -> G::ScalarField
where
    G::BaseField: PrimeField,
{
    let n1 = <G::ScalarField as PrimeField>::MODULUS;
    let n2 = <G::ScalarField as PrimeField>::BigInt::from_bits_le(
        &<G::BaseField as PrimeField>::MODULUS.to_bits_le()[..],
    );
    let two: G::ScalarField = (2u64).into();
    let two_pow = two.pow([<G::ScalarField as PrimeField>::MODULUS_BIT_SIZE as u64]);
    if n1 < n2 {
        (x - (two_pow + G::ScalarField::one())) / two
    } else {
        x - two_pow
    }
}

impl<'a, 'b, C: AffineRepr> Add<&'a PolyComm<C>> for &'b PolyComm<C> {
    type Output = PolyComm<C>;

    fn add(self, other: &'a PolyComm<C>) -> PolyComm<C> {
        let mut elems = vec![];
        let n1 = self.elems.len();
        let n2 = other.elems.len();
        for i in 0..std::cmp::max(n1, n2) {
            let pt = if i < n1 && i < n2 {
                (self.elems[i] + other.elems[i]).into_affine()
            } else if i < n1 {
                self.elems[i]
            } else {
                other.elems[i]
            };
            elems.push(pt);
        }
        PolyComm { elems }
    }
}

impl<'a, 'b, C: AffineRepr + Sub<Output = C::Group>> Sub<&'a PolyComm<C>> for &'b PolyComm<C> {
    type Output = PolyComm<C>;

    fn sub(self, other: &'a PolyComm<C>) -> PolyComm<C> {
        let mut elems = vec![];
        let n1 = self.elems.len();
        let n2 = other.elems.len();
        for i in 0..std::cmp::max(n1, n2) {
            let pt = if i < n1 && i < n2 {
                (self.elems[i] - other.elems[i]).into_affine()
            } else if i < n1 {
                self.elems[i]
            } else {
                other.elems[i]
            };
            elems.push(pt);
        }
        PolyComm { elems }
    }
}

impl<C: AffineRepr> PolyComm<C> {
    pub fn scale(&self, c: C::ScalarField) -> PolyComm<C> {
        PolyComm {
            elems: self.elems.iter().map(|g| g.mul(c).into_affine()).collect(),
        }
    }

    /// Performs a multi-scalar multiplication between scalars `elm` and commitments `com`.
    /// If both are empty, returns a commitment of length 1 containing the point at infinity.
    ///
    /// ## Panics
    ///
    /// Panics if `com` and `elm` are not of the same size.
    pub fn multi_scalar_mul(com: &[&PolyComm<C>], elm: &[C::ScalarField]) -> Self {
        assert_eq!(com.len(), elm.len());

        if com.is_empty() || elm.is_empty() {
            return Self::new(vec![C::zero()]);
        }

        let all_scalars: Vec<_> = elm.iter().map(|s| s.into_bigint()).collect();

        let elems_size = Iterator::max(com.iter().map(|c| c.elems.len())).unwrap();
        let mut elems = Vec::with_capacity(elems_size);

        for chunk in 0..elems_size {
            let (points, scalars): (Vec<_>, Vec<_>) = com
                .iter()
                .zip(&all_scalars)
                // get rid of scalars that don't have an associated chunk
                .filter_map(|(com, scalar)| com.elems.get(chunk).map(|c| (c, scalar)))
                .unzip();

            let chunk_msm = C::Group::msm_bigint(&points, &scalars);
            elems.push(chunk_msm.into_affine());
        }
        Self::new(elems)
    }
}

/// Returns the product of all the field elements belonging to an iterator.
pub fn product<F: Field>(xs: impl Iterator<Item = F>) -> F {
    let mut res = F::one();
    for x in xs {
        res *= &x;
    }
    res
}

/// Returns (1 + chal[-1] x)(1 + chal[-2] x^2)(1 + chal[-3] x^4) ...
/// It's "step 8: Define the univariate polynomial" of
/// appendix A.2 of <https://eprint.iacr.org/2020/499>
pub fn b_poly<F: Field>(chals: &[F], x: F) -> F {
    let k = chals.len();

    let mut pow_twos = vec![x];

    for i in 1..k {
        pow_twos.push(pow_twos[i - 1].square());
    }

    product((0..k).map(|i| (F::one() + (chals[i] * pow_twos[k - 1 - i]))))
}

pub fn b_poly_coefficients<F: Field>(chals: &[F]) -> Vec<F> {
    let rounds = chals.len();
    let s_length = 1 << rounds;
    let mut s = vec![F::one(); s_length];
    let mut k: usize = 0;
    let mut pow: usize = 1;
    for i in 1..s_length {
        k += if i == pow { 1 } else { 0 };
        pow <<= if i == pow { 1 } else { 0 };
        s[i] = s[i - (pow >> 1)] * chals[rounds - 1 - (k - 1)];
    }
    s
}

/// `pows(d, x)` returns a vector containing the first `d` powers of the field element `x` (from `1` to `x^(d-1)`).
pub fn pows<F: Field>(d: usize, x: F) -> Vec<F> {
    let mut acc = F::one();
    let mut res = vec![];
    for _ in 1..=d {
        res.push(acc);
        acc *= x;
    }
    res
}

pub fn squeeze_prechallenge<Fq: Field, G, Fr: Field, EFqSponge: FqSponge<Fq, G, Fr>>(
    sponge: &mut EFqSponge,
) -> ScalarChallenge<Fr> {
    ScalarChallenge(sponge.challenge())
}

pub fn squeeze_challenge<Fq: Field, G, Fr: PrimeField, EFqSponge: FqSponge<Fq, G, Fr>>(
    endo_r: &Fr,
    sponge: &mut EFqSponge,
) -> Fr {
    squeeze_prechallenge(sponge).to_field(endo_r)
}

pub fn absorb_commitment<Fq: Field, G: Clone, Fr: PrimeField, EFqSponge: FqSponge<Fq, G, Fr>>(
    sponge: &mut EFqSponge,
    commitment: &PolyComm<G>,
) {
    sponge.absorb_g(&commitment.elems);
}

/// A useful trait extending AffineRepr for commitments.
/// Unfortunately, we can't specify that `AffineRepr<BaseField : PrimeField>`,
/// so usage of this traits must manually bind `G::BaseField: PrimeField`.
pub trait CommitmentCurve: AffineRepr + Sub<Output = Self::Group> {
    type Params: SWCurveConfig;
    type Map: GroupMap<Self::BaseField>;

    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)>;
    fn of_coordinates(x: Self::BaseField, y: Self::BaseField) -> Self;
}

/// A trait extending CommitmentCurve for endomorphisms.
/// Unfortunately, we can't specify that `AffineCurve<BaseField : PrimeField>`,
/// so usage of this traits must manually bind `G::BaseField: PrimeField`.
pub trait EndoCurve: CommitmentCurve {
    /// Combine where x1 = one
    fn combine_one(g1: &[Self], g2: &[Self], x2: Self::ScalarField) -> Vec<Self> {
        crate::combine::window_combine(g1, g2, Self::ScalarField::one(), x2)
    }

    /// Combine where x1 = one
    fn combine_one_endo(
        endo_r: Self::ScalarField,
        _endo_q: Self::BaseField,
        g1: &[Self],
        g2: &[Self],
        x2: ScalarChallenge<Self::ScalarField>,
    ) -> Vec<Self> {
        crate::combine::window_combine(g1, g2, Self::ScalarField::one(), x2.to_field(&endo_r))
    }

    fn combine(
        g1: &[Self],
        g2: &[Self],
        x1: Self::ScalarField,
        x2: Self::ScalarField,
    ) -> Vec<Self> {
        crate::combine::window_combine(g1, g2, x1, x2)
    }
}

impl<P: SWCurveConfig + Clone> CommitmentCurve for SWJAffine<P> {
    type Params = P;
    type Map = BWParameters<P>;

    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)> {
        if self.infinity {
            None
        } else {
            Some((self.x, self.y))
        }
    }

    fn of_coordinates(x: P::BaseField, y: P::BaseField) -> SWJAffine<P> {
        SWJAffine::<P>::new_unchecked(x, y)
    }
}

impl<P: SWCurveConfig + Clone> EndoCurve for SWJAffine<P> {
    fn combine_one(g1: &[Self], g2: &[Self], x2: Self::ScalarField) -> Vec<Self> {
        crate::combine::affine_window_combine_one(g1, g2, x2)
    }

    fn combine_one_endo(
        _endo_r: Self::ScalarField,
        endo_q: Self::BaseField,
        g1: &[Self],
        g2: &[Self],
        x2: ScalarChallenge<Self::ScalarField>,
    ) -> Vec<Self> {
        crate::combine::affine_window_combine_one_endo(endo_q, g1, g2, x2)
    }

    fn combine(
        g1: &[Self],
        g2: &[Self],
        x1: Self::ScalarField,
        x2: Self::ScalarField,
    ) -> Vec<Self> {
        crate::combine::affine_window_combine(g1, g2, x1, x2)
    }
}

pub fn to_group<G: CommitmentCurve>(m: &G::Map, t: <G as AffineRepr>::BaseField) -> G {
    let (x, y) = m.to_group(t);
    G::of_coordinates(x, y)
}

/// Computes the linearization of the evaluations of a (potentially split) polynomial.
/// Each given `poly` is associated to a matrix where the rows represent the number of evaluated points,
/// and the columns represent potential segments (if a polynomial was split in several parts).
#[allow(clippy::type_complexity)]
pub fn combined_inner_product<F: PrimeField>(
    polyscale: &F,
    evalscale: &F,
    // TODO(mimoo): needs a type that can get you evaluations or segments
    polys: &[Vec<Vec<F>>],
) -> F {
    let mut res = F::zero();
    let mut xi_i = F::one();

    for evals_tr in polys.iter().filter(|evals_tr| !evals_tr[0].is_empty()) {
        // transpose the evaluations
        let evals = (0..evals_tr[0].len())
            .map(|i| evals_tr.iter().map(|v| v[i]).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // iterating over the polynomial segments
        for eval in &evals {
            let term = DensePolynomial::<F>::eval_polynomial(eval, *evalscale);

            res += &(xi_i * term);
            xi_i *= polyscale;
        }
    }
    res
}

/// Contains the evaluation of a polynomial commitment at a set of points.
pub struct Evaluation<G>
where
    G: AffineRepr,
{
    /// The commitment of the polynomial being evaluated
    pub commitment: PolyComm<G>,

    /// Contains an evaluation table
    pub evaluations: Vec<Vec<G::ScalarField>>,
}

/// Contains the batch evaluation
// TODO: I think we should really change this name to something more correct
pub struct BatchEvaluationProof<'a, G, EFqSponge, OpeningProof>
where
    G: AffineRepr,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
{
    pub sponge: EFqSponge,
    pub evaluations: Vec<Evaluation<G>>,
    /// vector of evaluation points
    pub evaluation_points: Vec<G::ScalarField>,
    /// scaling factor for evaluation point powers
    pub polyscale: G::ScalarField,
    /// scaling factor for polynomials
    pub evalscale: G::ScalarField,
    /// batched opening proof
    pub opening: &'a OpeningProof,
    pub combined_inner_product: G::ScalarField,
}

pub fn combine_commitments<G: CommitmentCurve>(
    evaluations: &[Evaluation<G>],
    scalars: &mut Vec<G::ScalarField>,
    points: &mut Vec<G>,
    polyscale: G::ScalarField,
    rand_base: G::ScalarField,
) {
    let mut xi_i = G::ScalarField::one();

    for Evaluation { commitment, .. } in evaluations
        .iter()
        .filter(|x| !x.commitment.elems.is_empty())
    {
        // iterating over the polynomial segments
        for comm_ch in &commitment.elems {
            scalars.push(rand_base * xi_i);
            points.push(*comm_ch);

            xi_i *= polyscale;
        }
    }
}

pub fn combine_evaluations<G: CommitmentCurve>(
    evaluations: &Vec<Evaluation<G>>,
    polyscale: G::ScalarField,
) -> Vec<G::ScalarField> {
    let mut xi_i = G::ScalarField::one();
    let mut acc = {
        let num_evals = if !evaluations.is_empty() {
            evaluations[0].evaluations.len()
        } else {
            0
        };
        vec![G::ScalarField::zero(); num_evals]
    };

    for Evaluation { evaluations, .. } in evaluations
        .iter()
        .filter(|x| !x.commitment.elems.is_empty())
    {
        // iterating over the polynomial segments
        for j in 0..evaluations[0].len() {
            for i in 0..evaluations.len() {
                acc[i] += evaluations[i][j] * xi_i;
            }
            xi_i *= polyscale;
        }
    }

    acc
}

impl<G: CommitmentCurve> SRSTrait<G> for SRS<G> {
    /// The maximum polynomial degree that can be committed to
    fn max_poly_size(&self) -> usize {
        self.g.len()
    }

    fn get_lagrange_basis(&self, domain_size: usize) -> &Vec<PolyComm<G>> {
        self.get_lagrange_basis_from_domain_size(domain_size)
    }

    fn blinding_commitment(&self) -> G {
        self.h
    }

    /// Commits a polynomial, potentially splitting the result in multiple commitments.
    fn commit(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.mask(self.commit_non_hiding(plnm, num_chunks), rng)
    }

    /// Turns a non-hiding polynomial commitment into a hidding polynomial commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with a random `w` per commitment.
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

    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G> {
        let basis = self.get_lagrange_basis(domain);
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
                panic!("desired commitment domain size greater than evaluations' domain size")
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
}

impl<G: CommitmentCurve> SRS<G> {
    /// This function verifies batch of batched polynomial commitment opening proofs
    ///     batch: batch of batched polynomial commitment opening proofs
    ///          vector of evaluation points
    ///          polynomial scaling factor for this batched openinig proof
    ///          eval scaling factor for this batched openinig proof
    ///          batch/vector of polycommitments (opened in this batch), evaluation vectors and, optionally, max degrees
    ///          opening proof for this batched opening
    ///     oracle_params: parameters for the random oracle argument
    ///     randomness source context
    ///     RETURN: verification status
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
            let u: G = to_group(group_map, t);

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
}

pub fn inner_prod<F: Field>(xs: &[F], ys: &[F]) -> F {
    let mut res = F::zero();
    for (&x, y) in xs.iter().zip(ys) {
        res += &(x * y);
    }
    res
}

//
// OCaml types
//

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;

    // polynomial commitment

    #[derive(Clone, Debug, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlPolyComm<CamlG> {
        pub unshifted: Vec<CamlG>,
        pub shifted: Option<CamlG>,
    }

    // handy conversions

    impl<G, CamlG> From<PolyComm<G>> for CamlPolyComm<CamlG>
    where
        G: AffineRepr,
        CamlG: From<G>,
    {
        fn from(polycomm: PolyComm<G>) -> Self {
            Self {
                unshifted: polycomm.elems.into_iter().map(CamlG::from).collect(),
                shifted: None,
            }
        }
    }

    impl<'a, G, CamlG> From<&'a PolyComm<G>> for CamlPolyComm<CamlG>
    where
        G: AffineRepr,
        CamlG: From<G> + From<&'a G>,
    {
        fn from(polycomm: &'a PolyComm<G>) -> Self {
            Self {
                unshifted: polycomm.elems.iter().map(Into::<CamlG>::into).collect(),
                shifted: None,
            }
        }
    }

    impl<G, CamlG> From<CamlPolyComm<CamlG>> for PolyComm<G>
    where
        G: AffineRepr + From<CamlG>,
    {
        fn from(camlpolycomm: CamlPolyComm<CamlG>) -> PolyComm<G> {
            assert!(
                camlpolycomm.shifted.is_none(),
                "mina#14628: Shifted commitments are deprecated and must not be used"
            );
            PolyComm {
                elems: camlpolycomm
                    .unshifted
                    .into_iter()
                    .map(Into::<G>::into)
                    .collect(),
            }
        }
    }

    impl<'a, G, CamlG> From<&'a CamlPolyComm<CamlG>> for PolyComm<G>
    where
        G: AffineRepr + From<&'a CamlG> + From<CamlG>,
    {
        fn from(camlpolycomm: &'a CamlPolyComm<CamlG>) -> PolyComm<G> {
            assert!(
                camlpolycomm.shifted.is_none(),
                "mina#14628: Shifted commitments are deprecated and must not be used"
            );
            PolyComm {
                //FIXME something with as_ref()
                elems: camlpolycomm.unshifted.iter().map(Into::into).collect(),
            }
        }
    }

    // opening proof

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

pub mod test_common {
    use super::*;

    use crate::{
        commitment::{
            combined_inner_product, BatchEvaluationProof, BlindedCommitment, CommitmentCurve,
            Evaluation, PolyComm,
        },
        evaluation_proof::{DensePolynomialOrEvaluations, OpeningProof},
        srs::SRS,
        SRS as SRSTrait,
    };
    use ark_ff::{UniformRand, Zero};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi as SC, sponge::DefaultFqSponge, FqSponge,
    };
    use rand::{CryptoRng, Rng};
    use std::{
        iter::Iterator,
        time::{Duration, Instant},
    };

    // Note: Because the current API uses large tuples of types, I re-create types
    // in this test to facilitate aggregated proofs and batch verification of proofs.
    // TODO: improve the polynomial commitment API

    /// A commitment
    pub struct Commitment {
        /// the commitment itself, potentially in chunks
        chunked_commitment: PolyComm<Vesta>,
    }

    /// An evaluated commitment (given a number of evaluation points)
    pub struct EvaluatedCommitment {
        /// the commitment
        commit: Commitment,
        /// the chunked evaluations given in the same order as the evaluation points
        chunked_evals: Vec<ChunkedCommitmentEvaluation>,
    }

    /// A polynomial commitment evaluated at a point. Since a commitment can be chunked, the evaluations can also be chunked.
    pub type ChunkedCommitmentEvaluation = Vec<Fp>;

    mod prover {
        use super::*;

        /// This struct represents a commitment with associated secret information
        pub struct CommitmentAndSecrets {
            /// the commitment evaluated at some points
            pub eval_commit: EvaluatedCommitment,
            /// the polynomial
            pub poly: DensePolynomial<Fp>,
            /// the blinding part
            pub chunked_blinding: PolyComm<Fp>,
        }
    }

    /// This struct represents an aggregated evaluation proof for a number of polynomial commitments, as well as a number of evaluation points.
    pub struct AggregatedEvaluationProof {
        /// a number of evaluation points
        eval_points: Vec<Fp>,
        /// a number of commitments evaluated at these evaluation points
        eval_commitments: Vec<EvaluatedCommitment>,
        /// the random value used to separate polynomials
        polymask: Fp,
        /// the random value used to separate evaluations
        evalmask: Fp,
        /// an Fq-sponge
        fq_sponge: DefaultFqSponge<VestaParameters, SC>,
        /// the actual evaluation proof
        pub proof: OpeningProof<Vesta>,
    }

    impl AggregatedEvaluationProof {
        /// This function converts an aggregated evaluation proof into something the verify API understands
        pub fn verify_type(
            &self,
        ) -> BatchEvaluationProof<Vesta, DefaultFqSponge<VestaParameters, SC>, OpeningProof<Vesta>>
        {
            let mut coms = vec![];
            for eval_com in &self.eval_commitments {
                assert_eq!(self.eval_points.len(), eval_com.chunked_evals.len());
                coms.push(Evaluation {
                    commitment: eval_com.commit.chunked_commitment.clone(),
                    evaluations: eval_com.chunked_evals.clone(),
                });
            }

            let combined_inner_product = {
                let es: Vec<_> = coms
                    .iter()
                    .map(|Evaluation { evaluations, .. }| evaluations.clone())
                    .collect();
                combined_inner_product(&self.polymask, &self.evalmask, &es)
            };

            BatchEvaluationProof {
                sponge: self.fq_sponge.clone(),
                evaluation_points: self.eval_points.clone(),
                polyscale: self.polymask,
                evalscale: self.evalmask,
                evaluations: coms,
                opening: &self.proof,
                combined_inner_product,
            }
        }
    }

    pub fn generate_random_opening_proof<RNG: Rng + CryptoRng>(
        mut rng: &mut RNG,
        group_map: &<Vesta as CommitmentCurve>::Map,
        srs: &SRS<Vesta>,
    ) -> (Vec<AggregatedEvaluationProof>, Duration, Duration) {
        let num_chunks = 1;

        let fq_sponge = DefaultFqSponge::<VestaParameters, SC>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );

        let mut time_commit = Duration::new(0, 0);
        let mut time_open = Duration::new(0, 0);

        // create 7 distinct "aggregated evaluation proofs"
        let mut proofs = vec![];
        for _ in 0..7 {
            // generate 7 random evaluation points
            let eval_points: Vec<Fp> = (0..7).map(|_| Fp::rand(&mut rng)).collect();

            // create 11 polynomials of random degree (of at most 500)
            // and commit to them
            let mut commitments = vec![];
            for _ in 0..11 {
                let len: usize = rng.gen();
                let len = len % 500;
                // TODO @volhovm maybe remove the second case.
                // every other polynomial is upperbounded
                let poly = if len == 0 {
                    DensePolynomial::<Fp>::zero()
                } else {
                    DensePolynomial::<Fp>::rand(len, &mut rng)
                };

                // create commitments for each polynomial, and evaluate each polynomial at the 7 random points
                let timer = Instant::now();
                let BlindedCommitment {
                    commitment: chunked_commitment,
                    blinders: chunked_blinding,
                } = srs.commit(&poly, num_chunks, &mut rng);
                time_commit += timer.elapsed();

                let mut chunked_evals = vec![];
                for point in eval_points.clone() {
                    let n = poly.len();
                    let num_chunks = if n == 0 {
                        1
                    } else {
                        n / srs.g.len() + if n % srs.g.len() == 0 { 0 } else { 1 }
                    };
                    chunked_evals.push(
                        poly.to_chunked_polynomial(num_chunks, srs.g.len())
                            .evaluate_chunks(point),
                    );
                }

                let commit = Commitment { chunked_commitment };

                let eval_commit = EvaluatedCommitment {
                    commit,
                    chunked_evals,
                };

                commitments.push(prover::CommitmentAndSecrets {
                    eval_commit,
                    poly,
                    chunked_blinding,
                });
            }

            // create aggregated evaluation proof
            #[allow(clippy::type_complexity)]
            let mut polynomials: Vec<(
                DensePolynomialOrEvaluations<Fp, Radix2EvaluationDomain<Fp>>,
                PolyComm<_>,
            )> = vec![];
            for c in &commitments {
                polynomials.push((
                    DensePolynomialOrEvaluations::DensePolynomial(&c.poly),
                    c.chunked_blinding.clone(),
                ));
            }

            let polymask = Fp::rand(&mut rng);
            let evalmask = Fp::rand(&mut rng);

            let timer = Instant::now();
            let proof = srs.open::<DefaultFqSponge<VestaParameters, SC>, _, _>(
                group_map,
                &polynomials,
                &eval_points.clone(),
                polymask,
                evalmask,
                fq_sponge.clone(),
                &mut rng,
            );
            time_open += timer.elapsed();

            // prepare for batch verification
            let eval_commitments = commitments.into_iter().map(|c| c.eval_commit).collect();
            proofs.push(AggregatedEvaluationProof {
                eval_points,
                eval_commitments,
                polymask,
                evalmask,
                fq_sponge: fq_sponge.clone(),
                proof,
            });
        }

        (proofs, time_commit, time_open)
    }
}
