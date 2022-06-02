//! This module implements Dlog-based polynomial commitment schema.
//! The folowing functionality is implemented
//!
//! 1. Commit to polynomial with its max degree
//! 2. Open polynomial commitment batch at the given evaluation point and scaling factor scalar
//!     producing the batched opening proof
//! 3. Verify batch of batched opening proofs

use crate::srs::SRS;
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
use o1_utils::math;
use o1_utils::types::fields::*;
use o1_utils::ExtendedDensePolynomial as _;
use oracle::{sponge::ScalarChallenge, FqSponge};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::iter::Iterator;

use super::evaluation_proof::*;

/// A polynomial commitment.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolyComm<C>
where
    C: CanonicalDeserialize + CanonicalSerialize,
{
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub unshifted: Vec<C>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub shifted: Option<C>,
}

impl<A: Copy> PolyComm<A>
where
    A: CanonicalDeserialize + CanonicalSerialize,
{
    pub fn map<B, F>(&self, mut f: F) -> PolyComm<B>
    where
        F: FnMut(A) -> B,
        B: CanonicalDeserialize + CanonicalSerialize,
    {
        let unshifted = self.unshifted.iter().map(|x| f(*x)).collect();
        let shifted = self.shifted.map(f);
        PolyComm { unshifted, shifted }
    }
}

impl<A: Copy, B: Copy> PolyComm<(A, B)>
where
    A: CanonicalDeserialize + CanonicalSerialize,
    B: CanonicalDeserialize + CanonicalSerialize,
{
    fn unzip(self) -> (PolyComm<A>, PolyComm<B>) {
        let a = self.map(|(x, _)| x);
        let b = self.map(|(_, y)| y);
        (a, b)
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
    let two_pow = two.pow(&[<G::ScalarField as PrimeField>::Params::MODULUS_BITS as u64]);
    if n1 < n2 {
        (x - (two_pow + G::ScalarField::one())) / two
    } else {
        x - two_pow
    }
}

impl<'a, 'b, C: AffineCurve> Add<&'a PolyComm<C>> for &'b PolyComm<C> {
    type Output = PolyComm<C>;

    fn add(self, other: &'a PolyComm<C>) -> PolyComm<C> {
        let mut unshifted = vec![];
        let n1 = self.unshifted.len();
        let n2 = other.unshifted.len();
        for i in 0..std::cmp::max(n1, n2) {
            let pt = if i < n1 && i < n2 {
                self.unshifted[i] + other.unshifted[i]
            } else if i < n1 {
                self.unshifted[i]
            } else {
                other.unshifted[i]
            };
            unshifted.push(pt);
        }
        let shifted = match (self.shifted, other.shifted) {
            (None, _) => other.shifted,
            (_, None) => self.shifted,
            (Some(p1), Some(p2)) => Some(p1 + p2),
        };
        PolyComm { unshifted, shifted }
    }
}

impl<'a, 'b, C: AffineCurve> Sub<&'a PolyComm<C>> for &'b PolyComm<C> {
    type Output = PolyComm<C>;

    fn sub(self, other: &'a PolyComm<C>) -> PolyComm<C> {
        let mut unshifted = vec![];
        let n1 = self.unshifted.len();
        let n2 = other.unshifted.len();
        for i in 0..std::cmp::max(n1, n2) {
            let pt = if i < n1 && i < n2 {
                self.unshifted[i] + (-other.unshifted[i])
            } else if i < n1 {
                self.unshifted[i]
            } else {
                other.unshifted[i]
            };
            unshifted.push(pt);
        }
        let shifted = match (self.shifted, other.shifted) {
            (None, _) => other.shifted,
            (_, None) => self.shifted,
            (Some(p1), Some(p2)) => Some(p1 + (-p2)),
        };
        PolyComm { unshifted, shifted }
    }
}

impl<C: AffineCurve> PolyComm<C> {
    pub fn scale(&self, c: C::ScalarField) -> PolyComm<C> {
        PolyComm {
            unshifted: self
                .unshifted
                .iter()
                .map(|g| g.mul(c).into_affine())
                .collect(),
            shifted: self.shifted.map(|g| g.mul(c).into_affine()),
        }
    }

    pub fn multi_scalar_mul(com: &[&PolyComm<C>], elm: &[C::ScalarField]) -> Self {
        assert_eq!(com.len(), elm.len());
        PolyComm::<C> {
            shifted: {
                let pairs = com
                    .iter()
                    .zip(elm.iter())
                    .filter_map(|(c, s)| c.shifted.map(|c| (c, s)))
                    .collect::<Vec<_>>();
                if pairs.is_empty() {
                    None
                } else {
                    let points = pairs.iter().map(|(c, _)| *c).collect::<Vec<_>>();
                    let scalars = pairs.iter().map(|(_, s)| s.into_repr()).collect::<Vec<_>>();
                    Some(VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine())
                }
            },
            unshifted: {
                if com.is_empty() || elm.is_empty() {
                    Vec::new()
                } else {
                    let n = Iterator::max(com.iter().map(|c| c.unshifted.len())).unwrap();
                    (0..n)
                        .map(|i| {
                            let mut points = Vec::new();
                            let mut scalars = Vec::new();
                            com.iter().zip(elm.iter()).for_each(|(p, s)| {
                                if i < p.unshifted.len() {
                                    points.push(p.unshifted[i]);
                                    scalars.push(s.into_repr())
                                }
                            });
                            VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine()
                        })
                        .collect::<Vec<_>>()
                }
            },
        }
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

pub trait CommitmentCurve: AffineCurve {
    type Params: SWModelParameters;
    type Map: GroupMap<Self::BaseField>;

    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)>;
    fn of_coordinates(x: Self::BaseField, y: Self::BaseField) -> Self;

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

impl<P: SWModelParameters> CommitmentCurve for SWJAffine<P>
where
    P::BaseField: PrimeField,
{
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

/// Computes the linearization of the evaluations of a (potentially split) polynomial.
/// Each given `poly` is associated to a matrix where the rows represent the number of evaluated points,
/// and the columns represent potential segments (if a polynomial was split in several parts).
/// Note that if one of the polynomial comes specified with a degree bound,
/// the evaluation for the last segment is potentially shifted to meet the proof.
#[allow(clippy::type_complexity)]
pub fn combined_inner_product<G: CommitmentCurve>(
    evaluation_points: &[ScalarField<G>],
    xi: &ScalarField<G>,
    r: &ScalarField<G>,
    // TODO(mimoo): needs a type that can get you evaluations or segments
    polys: &[(Vec<Vec<ScalarField<G>>>, Option<usize>)],
    srs_length: usize,
) -> ScalarField<G> {
    let mut res = ScalarField::<G>::zero();
    let mut xi_i = ScalarField::<G>::one();

    for (evals_tr, shifted) in polys.iter().filter(|(evals_tr, _)| !evals_tr[0].is_empty()) {
        // transpose the evaluations
        let evals = (0..evals_tr[0].len())
            .map(|i| evals_tr.iter().map(|v| v[i]).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // iterating over the polynomial segments
        for eval in evals.iter() {
            let term = DensePolynomial::<ScalarField<G>>::eval_polynomial(eval, *r);

            res += &(xi_i * term);
            xi_i *= xi;
        }

        if let Some(m) = shifted {
            // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
            let last_evals = if *m > evals.len() * srs_length {
                vec![ScalarField::<G>::zero(); evaluation_points.len()]
            } else {
                evals[evals.len() - 1].clone()
            };
            let shifted_evals: Vec<_> = evaluation_points
                .iter()
                .zip(last_evals.iter())
                .map(|(elm, f_elm)| elm.pow(&[(srs_length - (*m) % srs_length) as u64]) * f_elm)
                .collect();

            res += &(xi_i * DensePolynomial::<ScalarField<G>>::eval_polynomial(&shifted_evals, *r));
            xi_i *= xi;
        }
    }
    res
}

/// Contains the evaluation of a polynomial commitment at a set of points.
pub struct Evaluation<G>
where
    G: AffineCurve,
{
    /// The commitment of the polynomial being evaluated
    pub commitment: PolyComm<G>,

    /// Contains an evaluation table
    pub evaluations: Vec<Vec<ScalarField<G>>>,

    /// optional degree bound
    pub degree_bound: Option<usize>,
}

/// Contains the batch evaluation
// TODO: I think we should really change this name to something more correct
pub struct BatchEvaluationProof<'a, G, EFqSponge>
where
    G: AffineCurve,
    EFqSponge: FqSponge<BaseField<G>, G, ScalarField<G>>,
{
    pub sponge: EFqSponge,
    pub evaluations: Vec<Evaluation<G>>,
    /// vector of evaluation points
    pub evaluation_points: Vec<ScalarField<G>>,
    /// scaling factor for evaluation point powers
    pub xi: ScalarField<G>,
    /// scaling factor for polynomials
    pub r: ScalarField<G>,
    /// batched opening proof
    pub opening: &'a OpeningProof<G>,
}

impl<G: CommitmentCurve> SRS<G> {
    /// Commits a polynomial, potentially splitting the result in multiple commitments.
    pub fn commit(
        &self,
        plnm: &DensePolynomial<ScalarField<G>>,
        max: Option<usize>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (PolyComm<G>, PolyComm<ScalarField<G>>) {
        self.mask(self.commit_non_hiding(plnm, max), rng)
    }

    /// Turns a non-hiding polynomial commitment into a hidding polynomial commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with a random `w` per commitment.
    pub fn mask(
        &self,
        c: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (PolyComm<G>, PolyComm<ScalarField<G>>) {
        c.map(|g: G| {
            if g.is_zero() {
                // TODO: This leaks information when g is the identity!
                // We should change this so that we still mask in this case
                (g, ScalarField::<G>::zero())
            } else {
                let w = ScalarField::<G>::rand(rng);
                let mut g_masked = self.h.mul(w);
                g_masked.add_assign_mixed(&g);
                (g_masked.into_affine(), w)
            }
        })
        .unzip()
    }

    /// This function commits a polynomial using the SRS' basis of size `n`.
    /// - `plnm`: polynomial to commit to with max size of sections
    /// - `max`: maximal degree of the polynomial (not inclusive), if none, no degree bound
    /// The function returns an unbounded commitment vector (which splits the commitment into several commitments of size at most `n`),
    /// as well as an optional bounded commitment (if `max` is set).
    /// Note that a maximum degree cannot (and doesn't need to) be enforced via a shift if `max` is a multiple of `n`.
    pub fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<ScalarField<G>>,
        max: Option<usize>,
    ) -> PolyComm<G> {
        Self::commit_helper(&plnm.coeffs[..], &self.g[..], None, plnm.is_zero(), max)
    }

    pub fn commit_helper(
        scalars: &[ScalarField<G>],
        basis: &[G],
        n: Option<usize>,
        is_zero: bool,
        max: Option<usize>,
    ) -> PolyComm<G> {
        let n = match n {
            Some(n) => n,
            None => basis.len(),
        };
        let p = scalars.len();

        // committing all the segments without shifting
        let unshifted = if is_zero {
            Vec::new()
        } else {
            (0..p / n + if p % n != 0 { 1 } else { 0 })
                .map(|i| {
                    VariableBaseMSM::multi_scalar_mul(
                        basis,
                        &scalars[i * n..p]
                            .iter()
                            .map(|s| s.into_repr())
                            .collect::<Vec<_>>(),
                    )
                    .into_affine()
                })
                .collect()
        };

        // committing only last segment shifted to the right edge of SRS
        let shifted = match max {
            None => None,
            Some(max) => {
                let start = max - (max % n);
                if is_zero || start >= p {
                    Some(G::zero())
                } else if max % n == 0 {
                    None
                } else {
                    Some(
                        VariableBaseMSM::multi_scalar_mul(
                            &basis[n - (max % n)..],
                            &scalars[start..p]
                                .iter()
                                .map(|s| s.into_repr())
                                .collect::<Vec<_>>(),
                        )
                        .into_affine(),
                    )
                }
            }
        };

        PolyComm::<G> { unshifted, shifted }
    }

    pub fn commit_evaluations_non_hiding(
        &self,
        domain: D<ScalarField<G>>,
        plnm: &Evaluations<ScalarField<G>, D<ScalarField<G>>>,
        max: Option<usize>,
    ) -> PolyComm<G> {
        let is_zero = plnm.evals.iter().all(|x| x.is_zero());
        let basis = match self.lagrange_bases.get(&domain.size()) {
            None => panic!("lagrange bases for size {} not found", domain.size()),
            Some(v) => &v[..],
        };
        match domain.size.cmp(&plnm.domain().size) {
            std::cmp::Ordering::Less => {
                let s = (plnm.domain().size / domain.size) as usize;
                let v: Vec<_> = (0..(domain.size())).map(|i| plnm.evals[s * i]).collect();
                Self::commit_helper(&v[..], basis, None, is_zero, max)
            }
            std::cmp::Ordering::Equal => {
                Self::commit_helper(&plnm.evals[..], basis, None, is_zero, max)
            }
            std::cmp::Ordering::Greater => {
                panic!("desired commitment domain size greater than evaluations' domain size")
            }
        }
    }

    pub fn commit_evaluations(
        &self,
        domain: D<ScalarField<G>>,
        plnm: &Evaluations<ScalarField<G>, D<ScalarField<G>>>,
        max: Option<usize>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (PolyComm<G>, PolyComm<ScalarField<G>>) {
        self.mask(self.commit_evaluations_non_hiding(domain, plnm, max), rng)
    }

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
        batch: &mut [BatchEvaluationProof<G, EFqSponge>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<BaseField<G>, G, ScalarField<G>>,
        RNG: RngCore + CryptoRng,
        G::BaseField: PrimeField,
    {
        // Verifier checks for all i,
        // c_i Q_i + delta_i = z1_i (G_i + b_i U_i) + z2_i H
        //
        // if we sample r at random, it suffices to check
        //
        // 0 == sum_i r^i (c_i Q_i + delta_i - ( z1_i (G_i + b_i U_i) + z2_i H ))
        //
        // and because each G_i is a multiexp on the same array self.g, we
        // can batch the multiexp across proofs.
        //
        // So for each proof in the batch, we add onto our big multiexp the following terms
        // r^i c_i Q_i
        // r^i delta_i
        // - (r^i z1_i) G_i
        // - (r^i z2_i) H
        // - (r^i z1_i b_i) U_i

        // We also check that the sg component of the proof is equal to the polynomial commitment
        // to the "s" array

        let nonzero_length = self.g.len();

        let max_rounds = math::ceil_log2(nonzero_length);

        let padded_length = 1 << max_rounds;

        // TODO: This will need adjusting
        let padding = padded_length - nonzero_length;
        let mut points = vec![self.h];
        points.extend(self.g.clone());
        points.extend(vec![G::zero(); padding]);

        let mut scalars = vec![ScalarField::<G>::zero(); padded_length + 1];
        assert_eq!(scalars.len(), points.len());

        // sample randomiser to scale the proofs with
        let rand_base = ScalarField::<G>::rand(rng);
        let sg_rand_base = ScalarField::<G>::rand(rng);

        let mut rand_base_i = ScalarField::<G>::one();
        let mut sg_rand_base_i = ScalarField::<G>::one();

        for BatchEvaluationProof {
            sponge,
            evaluation_points,
            xi,
            r,
            evaluations,
            opening,
        } in batch.iter_mut()
        {
            // TODO: This computation is repeated in ProverProof::oracles
            let combined_inner_product0 = {
                let es: Vec<_> = evaluations
                    .iter()
                    .map(
                        |Evaluation {
                             commitment,
                             evaluations,
                             degree_bound,
                         }| {
                            let bound: Option<usize> = (|| {
                                let b = (*degree_bound)?;
                                let x = commitment.shifted?;
                                if x.is_zero() {
                                    None
                                } else {
                                    Some(b)
                                }
                            })();
                            (evaluations.clone(), bound)
                        },
                    )
                    .collect();
                combined_inner_product::<G>(evaluation_points, xi, r, &es, self.g.len())
            };

            sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product0)]);

            let t = sponge.challenge_fq();
            let u: G = to_group(group_map, t);

            let Challenges { chal, chal_inv } =
                opening.challenges::<EFqSponge>(&self.endo_r, sponge);

            sponge.absorb_g(&[opening.delta]);
            let c = ScalarChallenge(sponge.challenge()).to_field(&self.endo_r);

            // < s, sum_i r^i pows(evaluation_point[i]) >
            // ==
            // sum_i r^i < s, pows(evaluation_point[i]) >
            let b0 = {
                let mut scale = ScalarField::<G>::one();
                let mut res = ScalarField::<G>::zero();
                for &e in evaluation_points.iter() {
                    let term = b_poly(&chal, e);
                    res += &(scale * term);
                    scale *= *r;
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
            // sum_j r^j (sum_i xi^i f_i) (elm_j)
            // == sum_j sum_i r^j xi^i f_i(elm_j)
            // == sum_i xi^i sum_j r^j f_i(elm_j)
            {
                let mut xi_i = ScalarField::<G>::one();

                for Evaluation {
                    commitment,
                    degree_bound,
                    ..
                } in evaluations
                    .iter()
                    .filter(|x| !x.commitment.unshifted.is_empty())
                {
                    // iterating over the polynomial segments
                    for comm_ch in commitment.unshifted.iter() {
                        scalars.push(rand_base_i_c_i * xi_i);
                        points.push(*comm_ch);

                        xi_i *= *xi;
                    }

                    if let Some(_m) = degree_bound {
                        if let Some(comm_ch) = commitment.shifted {
                            if !comm_ch.is_zero() {
                                // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
                                scalars.push(rand_base_i_c_i * xi_i);
                                points.push(comm_ch);

                                xi_i *= *xi;
                            }
                        }
                    }
                }
            };

            scalars.push(rand_base_i_c_i * combined_inner_product0);
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
    use ark_poly::{Polynomial, UVPolynomial};
    use array_init::array_init;
    use mina_curves::pasta::{fp::Fp, vesta::Affine as VestaG};
    use oracle::constants::PlonkSpongeConstantsKimchi as SC;
    use oracle::{pasta::fq_kimchi::params as spongeFqParams, sponge::DefaultFqSponge};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_lagrange_commitments() {
        let n = 64;
        let domain = D::<Fp>::new(n).unwrap();

        let mut srs = SRS::<VestaG>::create(n);
        srs.add_lagrange_basis(domain);

        let expected_lagrange_commitments: Vec<_> = (0..n)
            .map(|i| {
                let mut e = vec![Fp::zero(); n];
                e[i] = Fp::one();
                let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
                let c = srs.commit_non_hiding(&p, None);
                assert!(c.shifted.is_none());
                assert_eq!(c.unshifted.len(), 1);
                c.unshifted[0]
            })
            .collect();

        let computed_lagrange_commitments = srs.lagrange_bases.get(&domain.size()).unwrap();
        for i in 0..n {
            assert_eq!(
                computed_lagrange_commitments[i],
                expected_lagrange_commitments[i]
            );
        }
    }

    #[test]
    fn test_opening_proof() {
        // create two polynomials
        let coeffs: [Fp; 10] = array_init(|i| Fp::from(i as u32));
        let poly1 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs);
        let poly2 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs[..5]);

        // create an SRS
        let srs = SRS::<VestaG>::create(20);
        let rng = &mut StdRng::from_seed([0u8; 32]);

        // commit the two polynomials (and upperbound the second one)
        let commitment = srs.commit(&poly1, None, rng);
        let upperbound = poly2.degree() + 1;
        let bounded_commitment = srs.commit(&poly2, Some(upperbound), rng);

        // create an aggregated opening proof
        let (u, v) = (Fp::rand(rng), Fp::rand(rng));
        let group_map = <VestaG as CommitmentCurve>::Map::setup();
        let sponge = DefaultFqSponge::<_, SC>::new(spongeFqParams());

        let polys = vec![
            (&poly1, None, commitment.1),
            (&poly2, Some(upperbound), bounded_commitment.1),
        ];
        let elm = vec![Fp::rand(rng), Fp::rand(rng)];

        let opening_proof = srs.open(&group_map, &polys, &elm, v, u, sponge.clone(), rng);

        // evaluate the polynomials at these two points
        let poly1_chunked_evals = vec![
            poly1
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[0]),
            poly1
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[1]),
        ];

        fn sum(c: &[Fp]) -> Fp {
            c.iter().fold(Fp::zero(), |a, &b| a + b)
        }

        assert_eq!(sum(&poly1_chunked_evals[0]), poly1.evaluate(&elm[0]));
        assert_eq!(sum(&poly1_chunked_evals[1]), poly1.evaluate(&elm[1]));

        let poly2_chunked_evals = vec![
            poly2
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[0]),
            poly2
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[1]),
        ];

        assert_eq!(sum(&poly2_chunked_evals[0]), poly2.evaluate(&elm[0]));
        assert_eq!(sum(&poly2_chunked_evals[1]), poly2.evaluate(&elm[1]));

        // verify the proof
        let mut batch = vec![BatchEvaluationProof {
            sponge,
            evaluation_points: elm.clone(),
            xi: v,
            r: u,
            evaluations: vec![
                Evaluation {
                    commitment: commitment.0,
                    evaluations: poly1_chunked_evals,
                    degree_bound: None,
                },
                Evaluation {
                    commitment: bounded_commitment.0,
                    evaluations: poly2_chunked_evals,
                    degree_bound: Some(upperbound),
                },
            ],
            opening: &opening_proof,
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
                unshifted: polycomm.unshifted.into_iter().map(Into::into).collect(),
                shifted: polycomm.shifted.map(Into::into),
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
                unshifted: polycomm.unshifted.iter().map(Into::into).collect(),
                shifted: polycomm.shifted.as_ref().map(Into::into),
            }
        }
    }

    impl<G, CamlG> From<CamlPolyComm<CamlG>> for PolyComm<G>
    where
        G: AffineCurve + From<CamlG>,
    {
        fn from(camlpolycomm: CamlPolyComm<CamlG>) -> PolyComm<G> {
            PolyComm {
                unshifted: camlpolycomm.unshifted.into_iter().map(Into::into).collect(),
                shifted: camlpolycomm.shifted.map(Into::into),
            }
        }
    }

    impl<'a, G, CamlG> From<&'a CamlPolyComm<CamlG>> for PolyComm<G>
    where
        G: AffineCurve + From<&'a CamlG> + From<CamlG>,
    {
        fn from(camlpolycomm: &'a CamlPolyComm<CamlG>) -> PolyComm<G> {
            PolyComm {
                unshifted: camlpolycomm.unshifted.iter().map(Into::into).collect(),
                shifted: camlpolycomm.shifted.as_ref().map(Into::into),
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

    impl<G, CamlF, CamlG> Into<OpeningProof<G>> for CamlOpeningProof<CamlG, CamlF>
    where
        G: AffineCurve,
        CamlG: Into<G>,
        CamlF: Into<G::ScalarField>,
    {
        fn into(self) -> OpeningProof<G> {
            OpeningProof {
                lr: self
                    .lr
                    .into_iter()
                    .map(|(g1, g2)| (g1.into(), g2.into()))
                    .collect(),
                delta: self.delta.into(),
                z1: self.z1.into(),
                z2: self.z2.into(),
                sg: self.sg.into(),
            }
        }
    }
}
