//! This module implements Dlog-based polynomial commitment schema.
//! The following functionality is implemented
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
    models::short_weierstrass_jacobian::GroupAffine as SWJAffine, msm::VariableBaseMSM,
    AffineCurve, ProjectiveCurve, SWModelParameters,
};
use ark_ff::{
    BigInteger, Field, FpParameters, One, PrimeField, SquareRootField, UniformRand, Zero,
};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::ops::{Add, Sub};
use groupmap::{BWParameters, GroupMap};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::{math, ExtendedDensePolynomial as _};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{de::Visitor, Deserialize, Serialize};
use serde_with::{
    de::DeserializeAsWrap, ser::SerializeAsWrap, serde_as, DeserializeAs, SerializeAs,
};
use std::{iter::Iterator, marker::PhantomData};

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

impl<T, U> SerializeAs<PolyComm<T>> for PolyComm<U>
where
    U: SerializeAs<T>,
{
    fn serialize_as<S>(source: &PolyComm<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(source.elems.iter().map(|e| SerializeAsWrap::<T, U>::new(e)))
    }
}

impl<'de, T, U> DeserializeAs<'de, PolyComm<T>> for PolyComm<U>
where
    U: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<PolyComm<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SeqVisitor<T, U> {
            marker: PhantomData<(T, U)>,
        }

        impl<'de, T, U> Visitor<'de> for SeqVisitor<T, U>
        where
            U: DeserializeAs<'de, T>,
        {
            type Value = PolyComm<T>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                #[allow(clippy::redundant_closure_call)]
                let mut elems = vec![];

                while let Some(value) = seq
                    .next_element()?
                    .map(|v: DeserializeAsWrap<T, U>| v.into_inner())
                {
                    elems.push(value);
                }

                Ok(PolyComm { elems })
            }
        }

        let visitor = SeqVisitor::<T, U> {
            marker: PhantomData,
        };
        deserializer.deserialize_seq(visitor)
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
pub fn shift_scalar<G: AffineCurve>(x: G::ScalarField) -> G::ScalarField
where
    G::BaseField: PrimeField,
{
    let n1 = <G::ScalarField as PrimeField>::Params::MODULUS;
    let n2 = <G::ScalarField as PrimeField>::BigInt::from_bits_le(
        &<G::BaseField as PrimeField>::Params::MODULUS.to_bits_le()[..],
    );
    let two: G::ScalarField = (2u64).into();
    let two_pow = two.pow([<G::ScalarField as PrimeField>::Params::MODULUS_BITS as u64]);
    if n1 < n2 {
        (x - (two_pow + G::ScalarField::one())) / two
    } else {
        x - two_pow
    }
}

impl<'a, 'b, C: AffineCurve> Add<&'a PolyComm<C>> for &'b PolyComm<C> {
    type Output = PolyComm<C>;

    fn add(self, other: &'a PolyComm<C>) -> PolyComm<C> {
        let mut elems = vec![];
        let n1 = self.elems.len();
        let n2 = other.elems.len();
        for i in 0..std::cmp::max(n1, n2) {
            let pt = if i < n1 && i < n2 {
                self.elems[i] + other.elems[i]
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

impl<'a, 'b, C: AffineCurve> Sub<&'a PolyComm<C>> for &'b PolyComm<C> {
    type Output = PolyComm<C>;

    fn sub(self, other: &'a PolyComm<C>) -> PolyComm<C> {
        let mut elems = vec![];
        let n1 = self.elems.len();
        let n2 = other.elems.len();
        for i in 0..std::cmp::max(n1, n2) {
            let pt = if i < n1 && i < n2 {
                self.elems[i] + (-other.elems[i])
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

impl<C: AffineCurve> PolyComm<C> {
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

        let all_scalars: Vec<_> = elm.iter().map(|s| s.into_repr()).collect();

        let elems_size = Iterator::max(com.iter().map(|c| c.elems.len())).unwrap();
        let mut elems = Vec::with_capacity(elems_size);

        for chunk in 0..elems_size {
            let (points, scalars): (Vec<_>, Vec<_>) = com
                .iter()
                .zip(&all_scalars)
                // get rid of scalars that don't have an associated chunk
                .filter_map(|(com, scalar)| com.elems.get(chunk).map(|c| (c, scalar)))
                .unzip();

            let chunk_msm = VariableBaseMSM::multi_scalar_mul::<C>(&points, &scalars);
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

pub fn squeeze_prechallenge<Fq: Field, G, Fr: SquareRootField, EFqSponge: FqSponge<Fq, G, Fr>>(
    sponge: &mut EFqSponge,
) -> ScalarChallenge<Fr> {
    ScalarChallenge(sponge.challenge())
}

pub fn squeeze_challenge<
    Fq: Field,
    G,
    Fr: PrimeField + SquareRootField,
    EFqSponge: FqSponge<Fq, G, Fr>,
>(
    endo_r: &Fr,
    sponge: &mut EFqSponge,
) -> Fr {
    squeeze_prechallenge(sponge).to_field(endo_r)
}

pub fn absorb_commitment<
    Fq: Field,
    G: Clone,
    Fr: PrimeField + SquareRootField,
    EFqSponge: FqSponge<Fq, G, Fr>,
>(
    sponge: &mut EFqSponge,
    commitment: &PolyComm<G>,
) {
    sponge.absorb_g(&commitment.elems);
}

/// A useful trait extending AffineCurve for commitments.
/// Unfortunately, we can't specify that `AffineCurve<BaseField : PrimeField>`,
/// so usage of this traits must manually bind `G::BaseField: PrimeField`.
pub trait CommitmentCurve: AffineCurve {
    type Params: SWModelParameters;
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

impl<P: SWModelParameters + Clone> CommitmentCurve for SWJAffine<P> {
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
        SWJAffine::<P>::new(x, y, false)
    }
}

impl<P: SWModelParameters + Clone> EndoCurve for SWJAffine<P>
where
    P::BaseField: PrimeField,
{
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

pub fn to_group<G: CommitmentCurve>(m: &G::Map, t: <G as AffineCurve>::BaseField) -> G {
    let (x, y) = m.to_group(t);
    G::of_coordinates(x, y)
}

/// Computes the linearization of the evaluations of a (potentially
/// split) polynomial.
///
/// Each polynomial in `polys` is represented by a matrix where the
/// rows correspond to evaluated points, and the columns represent
/// potential segments (if a polynomial was split in several parts).
///
/// Elements in `evaluation_points` are several discrete points on which
/// we evaluate polynomials, e.g. `[zeta,zeta*w]`. See `PointEvaluations`.
///
/// Note that if one of the polynomial comes specified with a degree
/// bound, the evaluation for the last segment is potentially shifted
/// to meet the proof.
///
/// Returns
/// ```text
/// |polys| |segments[k]|
///    Σ         Σ         polyscale^{k*n+i} (Σ polys[k][j][i] * evalscale^j)
///  k = 1     i = 1                          j
/// ```
#[allow(clippy::type_complexity)]
pub fn combined_inner_product<F: PrimeField>(
    polyscale: &F,
    evalscale: &F,
    // TODO(mimoo): needs a type that can get you evaluations or segments
    polys: &[Vec<Vec<F>>],
) -> F {
    // final combined evaluation result
    let mut res = F::zero();
    // polyscale^i
    let mut xi_i = F::one();

    for evals_tr in polys.iter().filter(|evals_tr| !evals_tr[0].is_empty()) {
        // Transpose the evaluations.
        // evals[i] = {evals_tr[j][i]}_j now corresponds to a column in evals_tr,
        // representing a segment.
        let evals: Vec<_> = (0..evals_tr[0].len())
            .map(|i| evals_tr.iter().map(|v| v[i]).collect::<Vec<_>>())
            .collect();

        // Iterating over the polynomial segments.
        // Each segment gets its own polyscale^i, each segment element j is multiplied by evalscale^j.
        // Given that xi_i = polyscale^i0 at this point, after this loop we have:
        //
        //    res += Σ polyscale^{i0+i} ( Σ evals_tr[j][i] * evalscale^j )
        //           i                    j
        //
        for eval in &evals {
            // p_i(evalscale)
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
    G: AffineCurve,
{
    /// The commitment of the polynomial being evaluated.
    /// Note that PolyComm contains a vector of commitments, which handles the
    /// case when chunking is used, i.e. when the polynomial degree is higher
    /// than the SRS size.
    pub commitment: PolyComm<G>,

    /// Contains an evaluation table. For instance, for vanilla PlonK, it
    /// would be a vector of (chunked) evaluations at ζ and ζω.
    /// The outer vector would be the evaluations at the different points (e.g.
    /// ζ and ζω for vanilla PlonK) and the inner vector would be the chunks of
    /// the polynomial.
    pub evaluations: Vec<Vec<G::ScalarField>>,
}

/// Contains the batch evaluation
// TODO: I think we should really change this name to something more correct
pub struct BatchEvaluationProof<'a, G, EFqSponge, OpeningProof>
where
    G: AffineCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
{
    /// The sponge used to generate/absorb the challenges.
    pub sponge: EFqSponge,
    /// A list of evaluations, each supposed to correspond to a different
    /// polynomial.
    pub evaluations: Vec<Evaluation<G>>,
    /// The actual evaluation points. Each field `evaluations` of each structure
    /// of `Evaluation` should have the same (outer) length.
    pub evaluation_points: Vec<G::ScalarField>,
    /// scaling factor for evaluation point powers
    pub polyscale: G::ScalarField,
    /// scaling factor for polynomials
    pub evalscale: G::ScalarField,
    /// batched opening proof
    pub opening: &'a OpeningProof,
    pub combined_inner_product: G::ScalarField,
}

/// This function populates the parameters `scalars` and `points`.
/// It iterates over the evaluations and adds each commitment to the
/// vector `points`.
/// The parameter `scalars` is populated with the values:
/// `rand_base * polyscale^i` for each commitment.
/// For instance, if we have 3 commitments, the `scalars` vector will
/// contain the values
/// ```text
/// [rand_base, rand_base * polyscale, rand_base * polyscale^2]`
/// ```
/// and the vector `points` will contain the commitments.
///
/// Note that the function skips the commitments that are empty.
///
/// If more than one commitment is present in a single evaluation (i.e. if
/// `elems` is larger than one), it means that probably chunking was used (i.e.
/// it is a commitment to a polynomial larger than the SRS).
pub fn combine_commitments<G: CommitmentCurve>(
    evaluations: &[Evaluation<G>],
    scalars: &mut Vec<G::ScalarField>,
    points: &mut Vec<G>,
    polyscale: G::ScalarField,
    rand_base: G::ScalarField,
) {
    // will contain the power of polyscale
    let mut xi_i = G::ScalarField::one();

    for Evaluation { commitment, .. } in evaluations
        .iter()
        .filter(|x| !x.commitment.elems.is_empty())
    {
        // iterating over the polynomial segments
        for comm_ch in &commitment.elems {
            scalars.push(rand_base * xi_i);
            points.push(*comm_ch);

            // compute next power of polyscale
            xi_i *= polyscale;
        }
    }
}

/// Combine the (chunked) evaluations of multiple polynomials.
/// This function returns the accumulation of the evaluations, scaled by
/// `polyscale`.
/// If no evaluation is given, the function returns an empty vector.
/// It does also suppose that for each evaluation, the number of evaluations is
/// the same. It is not constrained yet in the interface, but it should be. If
/// one list has not the same size, it will be shrunk to the size of the first
/// element of the list.
/// For instance, if we have 3 polynomials P1, P2, P3 evaluated at the points
/// ζ and ζω (like in vanilla PlonK), and for each polynomial, we have two
/// chunks, i.e. we have
/// ```text
///         2 chunks of P1
///        /---------------\
/// E1 = [(P1_1(ζ), P1_2(ζ)), (P1_1(ζω), P1_2(ζω))]
/// E2 = [(P2_1(ζ), P2_2(ζ)), (P2_1(ζω), P2_2(ζω))]
/// E3 = [(P3_1(ζ), P3_2(ζ)), (P3_1(ζω), P3_2(ζω))]
/// ```
/// The output will be a list of 3 elements, equal to:
/// ```text
/// P1_1(ζ) + P1_2(ζ) * polyscale + P1_1(ζω) polyscale^2 + P1_2(ζω) * polyscale^3
/// P2_1(ζ) + P2_2(ζ) * polyscale + P2_1(ζω) polyscale^2 + P2_2(ζω) * polyscale^3
/// ```
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
        // IMPROVEME: we could have a flat array that would contain all the
        // evaluations and all the chunks. It would avoid fetching the memory
        // and avoid indirection into RAM.
        // We could have a single flat array.
        // iterating over the polynomial segments
        for chunk_idx in 0..evaluations[0].len() {
            // supposes that all evaluations are of the same size
            for eval_pt_idx in 0..evaluations.len() {
                acc[eval_pt_idx] += evaluations[eval_pt_idx][chunk_idx] * xi_i;
            }
            xi_i *= polyscale;
        }
    }

    acc
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
                g_masked.add_assign_mixed(&g);
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

        let coeffs: Vec<_> = plnm.iter().map(|c| c.into_repr()).collect();

        // chunk while commiting
        let mut elems = vec![];
        if is_zero {
            elems.push(G::zero());
        } else {
            coeffs.chunks(self.g.len()).for_each(|coeffs_chunk| {
                let chunk = VariableBaseMSM::multi_scalar_mul(&self.g, coeffs_chunk);
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
        let scalars: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();
        VariableBaseMSM::multi_scalar_mul(&points, &scalars) == G::Projective::zero()
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
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;

    use crate::srs::SRS;
    use ark_poly::{Polynomial, Radix2EvaluationDomain, UVPolynomial};
    use mina_curves::pasta::{Fp, Vesta as VestaG};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi as SC, sponge::DefaultFqSponge};
    use rand::{rngs::StdRng, SeedableRng};
    use std::array;

    #[test]
    fn test_combine_evaluations() {
        let nb_of_chunks = 1;

        // we ignore commitments
        let dummy_commitments = PolyComm::<VestaG> {
            elems: vec![VestaG::zero(); nb_of_chunks],
        };

        let polyscale = Fp::from(2);
        // Using only one evaluation. Starting with eval_p1
        {
            let eval_p1 = Evaluation {
                commitment: dummy_commitments.clone(),
                evaluations: vec![
                    // Eval at first point. Only one chunk.
                    vec![Fp::from(1)],
                    // Eval at second point. Only one chunk.
                    vec![Fp::from(2)],
                ],
            };

            let output = combine_evaluations::<VestaG>(&vec![eval_p1], polyscale);
            // We have 2 evaluation points.
            assert_eq!(output.len(), 2);
            // polyscale is not used.
            let exp_output = [Fp::from(1), Fp::from(2)];
            output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
                assert_eq!(o, e);
            });
        }

        // And after that eval_p2
        {
            let eval_p2 = Evaluation {
                commitment: dummy_commitments.clone(),
                evaluations: vec![
                    // Eval at first point. Only one chunk.
                    vec![Fp::from(3)],
                    // Eval at second point. Only one chunk.
                    vec![Fp::from(4)],
                ],
            };

            let output = combine_evaluations::<VestaG>(&vec![eval_p2], polyscale);
            // We have 2 evaluation points
            assert_eq!(output.len(), 2);
            // polyscale is not used.
            let exp_output = [Fp::from(3), Fp::from(4)];
            output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
                assert_eq!(o, e);
            });
        }

        // Now with two evaluations
        {
            let eval_p1 = Evaluation {
                commitment: dummy_commitments.clone(),
                evaluations: vec![
                    // Eval at first point. Only one chunk.
                    vec![Fp::from(1)],
                    // Eval at second point. Only one chunk.
                    vec![Fp::from(2)],
                ],
            };

            let eval_p2 = Evaluation {
                commitment: dummy_commitments.clone(),
                evaluations: vec![
                    // Eval at first point. Only one chunk.
                    vec![Fp::from(3)],
                    // Eval at second point. Only one chunk.
                    vec![Fp::from(4)],
                ],
            };

            let output = combine_evaluations::<VestaG>(&vec![eval_p1, eval_p2], polyscale);
            // We have 2 evaluation points
            assert_eq!(output.len(), 2);
            let exp_output = [Fp::from(1 + 3 * 2), Fp::from(2 + 4 * 2)];
            output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
                assert_eq!(o, e);
            });
        }

        // Now with two evaluations and two chunks
        {
            let eval_p1 = Evaluation {
                commitment: dummy_commitments.clone(),
                evaluations: vec![
                    // Eval at first point.
                    vec![Fp::from(1), Fp::from(3)],
                    // Eval at second point.
                    vec![Fp::from(2), Fp::from(4)],
                ],
            };

            let eval_p2 = Evaluation {
                commitment: dummy_commitments.clone(),
                evaluations: vec![
                    // Eval at first point.
                    vec![Fp::from(5), Fp::from(7)],
                    // Eval at second point.
                    vec![Fp::from(6), Fp::from(8)],
                ],
            };

            let output = combine_evaluations::<VestaG>(&vec![eval_p1, eval_p2], polyscale);
            // We have 2 evaluation points
            assert_eq!(output.len(), 2);
            let o1 = Fp::from(1 + 3 * 2 + 5 * 4 + 7 * 8);
            let o2 = Fp::from(2 + 4 * 2 + 6 * 4 + 8 * 8);
            let exp_output = [o1, o2];
            output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
                assert_eq!(o, e);
            });
        }
    }

    #[test]
    fn test_lagrange_commitments() {
        let n = 64;
        let domain = D::<Fp>::new(n).unwrap();

        let mut srs = SRS::<VestaG>::create(n);
        srs.add_lagrange_basis(domain);

        let num_chunks = domain.size() / srs.g.len();

        let expected_lagrange_commitments: Vec<_> = (0..n)
            .map(|i| {
                let mut e = vec![Fp::zero(); n];
                e[i] = Fp::one();
                let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
                srs.commit_non_hiding(&p, num_chunks)
            })
            .collect();

        let computed_lagrange_commitments = srs.lagrange_bases.get(&domain.size()).unwrap();
        for i in 0..n {
            assert_eq!(
                computed_lagrange_commitments[i],
                expected_lagrange_commitments[i],
            );
        }
    }

    #[test]
    // This tests with two chunks.
    fn test_chunked_lagrange_commitments() {
        let n = 64;
        let divisor = 4;
        let domain = D::<Fp>::new(n).unwrap();

        let mut srs = SRS::<VestaG>::create(n / divisor);
        srs.add_lagrange_basis(domain);

        let num_chunks = domain.size() / srs.g.len();
        assert!(num_chunks == divisor);

        let expected_lagrange_commitments: Vec<_> = (0..n)
            .map(|i| {
                let mut e = vec![Fp::zero(); n];
                e[i] = Fp::one();
                let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
                srs.commit_non_hiding(&p, num_chunks)
            })
            .collect();

        let computed_lagrange_commitments = srs.lagrange_bases.get(&domain.size()).unwrap();
        for i in 0..n {
            assert_eq!(
                computed_lagrange_commitments[i],
                expected_lagrange_commitments[i],
            );
        }
    }

    #[test]
    // TODO @volhovm I don't understand what this test does and
    // whether it is worth leaving.
    /// Same as test_chunked_lagrange_commitments, but with a slight
    /// offset in the SRS
    fn test_offset_chunked_lagrange_commitments() {
        let n = 64;
        let domain = D::<Fp>::new(n).unwrap();

        let mut srs = SRS::<VestaG>::create(n / 2 + 1);
        srs.add_lagrange_basis(domain);

        // Is this even taken into account?...
        let num_chunks = (domain.size() + srs.g.len() - 1) / srs.g.len();
        assert!(num_chunks == 2);

        let expected_lagrange_commitments: Vec<_> = (0..n)
            .map(|i| {
                let mut e = vec![Fp::zero(); n];
                e[i] = Fp::one();
                let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
                srs.commit_non_hiding(&p, num_chunks) // this requires max = Some(64)
            })
            .collect();

        let computed_lagrange_commitments = srs.lagrange_bases.get(&domain.size()).unwrap();
        for i in 0..n {
            assert_eq!(
                computed_lagrange_commitments[i],
                expected_lagrange_commitments[i],
            );
        }
    }

    #[test]
    fn test_opening_proof() {
        // create two polynomials
        let coeffs: [Fp; 10] = array::from_fn(|i| Fp::from(i as u32));
        let poly1 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs);
        let poly2 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs[..5]);

        // create an SRS
        let srs = SRS::<VestaG>::create(20);
        let rng = &mut StdRng::from_seed([0u8; 32]);

        // commit the two polynomials
        let commitment1 = srs.commit(&poly1, 1, rng);
        let commitment2 = srs.commit(&poly2, 1, rng);

        // create an aggregated opening proof
        let (u, v) = (Fp::rand(rng), Fp::rand(rng));
        let group_map = <VestaG as CommitmentCurve>::Map::setup();
        let sponge =
            DefaultFqSponge::<_, SC>::new(mina_poseidon::pasta::fq_kimchi::static_params());

        let polys: Vec<(
            DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
            PolyComm<_>,
        )> = vec![
            (
                DensePolynomialOrEvaluations::DensePolynomial(&poly1),
                commitment1.blinders,
            ),
            (
                DensePolynomialOrEvaluations::DensePolynomial(&poly2),
                commitment2.blinders,
            ),
        ];
        let elm = vec![Fp::rand(rng), Fp::rand(rng)];

        let opening_proof = srs.open(&group_map, &polys, &elm, v, u, sponge.clone(), rng);

        // evaluate the polynomials at these two points
        let poly1_chunked_evals = vec![
            poly1
                .to_chunked_polynomial(1, srs.g.len())
                .evaluate_chunks(elm[0]),
            poly1
                .to_chunked_polynomial(1, srs.g.len())
                .evaluate_chunks(elm[1]),
        ];

        fn sum(c: &[Fp]) -> Fp {
            c.iter().fold(Fp::zero(), |a, &b| a + b)
        }

        assert_eq!(sum(&poly1_chunked_evals[0]), poly1.evaluate(&elm[0]));
        assert_eq!(sum(&poly1_chunked_evals[1]), poly1.evaluate(&elm[1]));

        let poly2_chunked_evals = vec![
            poly2
                .to_chunked_polynomial(1, srs.g.len())
                .evaluate_chunks(elm[0]),
            poly2
                .to_chunked_polynomial(1, srs.g.len())
                .evaluate_chunks(elm[1]),
        ];

        assert_eq!(sum(&poly2_chunked_evals[0]), poly2.evaluate(&elm[0]));
        assert_eq!(sum(&poly2_chunked_evals[1]), poly2.evaluate(&elm[1]));

        let evaluations = vec![
            Evaluation {
                commitment: commitment1.commitment,
                evaluations: poly1_chunked_evals,
            },
            Evaluation {
                commitment: commitment2.commitment,
                evaluations: poly2_chunked_evals,
            },
        ];

        let combined_inner_product = {
            let es: Vec<_> = evaluations
                .iter()
                .map(|Evaluation { evaluations, .. }| evaluations.clone())
                .collect();
            combined_inner_product(&v, &u, &es)
        };

        // verify the proof
        let mut batch = vec![BatchEvaluationProof {
            sponge,
            evaluation_points: elm.clone(),
            polyscale: v,
            evalscale: u,
            evaluations,
            opening: &opening_proof,
            combined_inner_product,
        }];

        assert!(srs.verify(&group_map, &mut batch, rng));
    }
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
        G: AffineCurve,
        CamlG: From<G>,
    {
        fn from(polycomm: PolyComm<G>) -> Self {
            Self {
                unshifted: polycomm.elems.into_iter().map(Into::into).collect(),
                shifted: None,
            }
        }
    }

    impl<'a, G, CamlG> From<&'a PolyComm<G>> for CamlPolyComm<CamlG>
    where
        G: AffineCurve,
        CamlG: From<G> + From<&'a G>,
    {
        fn from(polycomm: &'a PolyComm<G>) -> Self {
            Self {
                unshifted: polycomm.elems.iter().map(Into::into).collect(),
                shifted: None,
            }
        }
    }

    impl<G, CamlG> From<CamlPolyComm<CamlG>> for PolyComm<G>
    where
        G: AffineCurve + From<CamlG>,
    {
        fn from(camlpolycomm: CamlPolyComm<CamlG>) -> PolyComm<G> {
            assert!(
                camlpolycomm.shifted.is_none(),
                "mina#14628: Shifted commitments are deprecated and must not be used"
            );
            PolyComm {
                elems: camlpolycomm.unshifted.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<'a, G, CamlG> From<&'a CamlPolyComm<CamlG>> for PolyComm<G>
    where
        G: AffineCurve + From<&'a CamlG> + From<CamlG>,
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
        G: AffineCurve,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(opening_proof: OpeningProof<G>) -> Self {
            Self {
                lr: opening_proof
                    .lr
                    .into_iter()
                    .map(|(g1, g2)| (g1.into(), g2.into()))
                    .collect(),
                delta: opening_proof.delta.into(),
                z1: opening_proof.z1.into(),
                z2: opening_proof.z2.into(),
                sg: opening_proof.sg.into(),
            }
        }
    }

    impl<G, CamlF, CamlG> From<CamlOpeningProof<CamlG, CamlF>> for OpeningProof<G>
    where
        G: AffineCurve,
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
