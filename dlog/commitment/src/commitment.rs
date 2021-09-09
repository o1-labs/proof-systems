/*****************************************************************************************************************

This source file implements Dlog-based polynomial commitment schema.
The folowing functionality is implemented

1. Commit to polynomial with its max degree
2. Open polynomial commitment batch at the given evaluation point and scaling factor scalar
    producing the batched opening proof
3. Verify batch of batched opening proofs

*****************************************************************************************************************/

use crate::srs::SRS;
pub use crate::CommitmentField;
use ark_ec::{
    models::short_weierstrass_jacobian::GroupAffine as SWJAffine, msm::VariableBaseMSM,
    AffineCurve, ProjectiveCurve, SWModelParameters,
};
use ark_ff::{Field, FpParameters, One, PrimeField, SquareRootField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use core::ops::{Add, Sub};
use groupmap::{BWParameters, GroupMap};
use o1_utils::ExtendedDensePolynomial as _;
use oracle::{sponge::ScalarChallenge, FqSponge};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::iter::Iterator;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

/// A polynomial commitment.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::IntoValue, ocaml::FromValue))]
pub struct PolyComm<C> {
    pub unshifted: Vec<C>,
    pub shifted: Option<C>,
}

impl<A: Copy> PolyComm<A> {
    pub fn map<B, F>(&self, mut f: F) -> PolyComm<B>
    where
        F: FnMut(A) -> B,
    {
        let unshifted = self.unshifted.iter().map(|x| f(*x)).collect();
        let shifted = self.shifted.map(f);
        PolyComm { unshifted, shifted }
    }
}

impl<A: Copy, B: Copy> PolyComm<(A, B)> {
    fn unzip(self) -> (PolyComm<A>, PolyComm<B>) {
        let a = self.map(|(x, _)| x);
        let b = self.map(|(_, y)| y);
        (a, b)
    }
}

pub fn shift_scalar<F: PrimeField>(x: F) -> F {
    let two: F = (2 as u64).into();
    x - two.pow(&[F::Params::MODULUS_BITS as u64])
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

    pub fn multi_scalar_mul(com: &Vec<&PolyComm<C>>, elm: &Vec<C::ScalarField>) -> Self {
        assert_eq!(com.len(), elm.len());
        PolyComm::<C> {
            shifted: {
                let pairs = com
                    .iter()
                    .zip(elm.iter())
                    .filter_map(|(c, s)| match c.shifted {
                        Some(c) => Some((c, s)),
                        None => None,
                    })
                    .collect::<Vec<_>>();
                if pairs.len() == 0 {
                    None
                } else {
                    let points = pairs.iter().map(|(c, _)| *c).collect::<Vec<_>>();
                    let scalars = pairs.iter().map(|(_, s)| s.into_repr()).collect::<Vec<_>>();
                    Some(VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine())
                }
            },
            unshifted: {
                if com.len() == 0 || elm.len() == 0 {
                    Vec::new()
                } else {
                    let n = com.iter().map(|c| c.unshifted.len()).max().unwrap();
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

#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::IntoValue, ocaml::FromValue))]
pub struct OpeningProof<G: AffineCurve> {
    pub lr: Vec<(G, G)>, // vector of rounds of L & R commitments
    pub delta: G,
    pub z1: G::ScalarField,
    pub z2: G::ScalarField,
    pub sg: G,
}

pub struct Challenges<F> {
    pub chal: Vec<F>,
    pub chal_inv: Vec<F>,
}

impl<G: AffineCurve> OpeningProof<G>
where
    G::ScalarField: CommitmentField,
{
    pub fn prechallenges<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        sponge: &mut EFqSponge,
    ) -> Vec<ScalarChallenge<Fr<G>>> {
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

    pub fn challenges<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        endo_r: &Fr<G>,
        sponge: &mut EFqSponge,
    ) -> Challenges<Fr<G>> {
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
/// appendix A.2 of https://eprint.iacr.org/2020/499
pub fn b_poly<F: Field>(chals: &Vec<F>, x: F) -> F {
    let k = chals.len();

    let mut pow_twos = vec![x];

    for i in 1..k {
        pow_twos.push(pow_twos[i - 1].square());
    }

    product((0..k).map(|i| (F::one() + &(chals[i] * &pow_twos[k - 1 - i]))))
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
        s[i] = s[i - (pow >> 1)] * &chals[rounds - 1 - (k - 1)];
    }
    s
}

// TODO: move to utils
/// Returns ceil(log2(d)) but panics if d = 0.
pub fn ceil_log2(d: usize) -> usize {
    assert!(d != 0);
    let mut pow2 = 1;
    let mut ceil_log2 = 0;
    while d > pow2 {
        ceil_log2 += 1;
        pow2 = match pow2.checked_mul(2) {
            Some(x) => x,
            None => break,
        }
    }
    ceil_log2
}

/// `pows(d, x)` returns a vector containing the first `d` powers of the field element `x` (from `1` to `x^(d-1)`).
fn pows<F: Field>(d: usize, x: F) -> Vec<F> {
    let mut acc = F::one();
    let mut res = vec![];
    for _ in 1..=d {
        res.push(acc);
        acc *= x;
    }
    res
}

fn squeeze_prechallenge<Fq: Field, G, Fr: SquareRootField, EFqSponge: FqSponge<Fq, G, Fr>>(
    sponge: &mut EFqSponge,
) -> ScalarChallenge<Fr> {
    ScalarChallenge(sponge.challenge())
}

fn squeeze_challenge<
    Fq: Field,
    G,
    Fr: PrimeField + CommitmentField,
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

    // Combine where x1 = one
    fn combine_one(g1: &Vec<Self>, g2: &Vec<Self>, x2: Self::ScalarField) -> Vec<Self> {
        crate::combine::window_combine(g1, g2, Self::ScalarField::one(), x2)
    }

    fn combine(
        g1: &Vec<Self>,
        g2: &Vec<Self>,
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

    fn combine_one(g1: &Vec<Self>, g2: &Vec<Self>, x2: Self::ScalarField) -> Vec<Self> {
        crate::combine::affine_window_combine_one(g1, g2, x2)
    }

    fn combine(
        g1: &Vec<Self>,
        g2: &Vec<Self>,
        x1: Self::ScalarField,
        x2: Self::ScalarField,
    ) -> Vec<Self> {
        crate::combine::affine_window_combine(g1, g2, x1, x2)
    }
}

fn to_group<G: CommitmentCurve>(m: &G::Map, t: <G as AffineCurve>::BaseField) -> G {
    let (x, y) = m.to_group(t);
    G::of_coordinates(x, y)
}

/// Computes the linearization of the evaluations of a (potentially split) polynomial.
/// Each given `poly` is associated to a matrix where the rows represent the number of evaluated points,
/// and the columns represent potential segments (if a polynomial was split in several parts).
/// Note that if one of the polynomial comes specified with a degree bound,
/// the evaluation for the last segment is potentially shifted to meet the proof.
pub fn combined_inner_product<G: CommitmentCurve>(
    evaluation_points: &[Fr<G>],
    xi: &Fr<G>,
    r: &Fr<G>,
    // TODO(mimoo): needs a type that can get you evaluations or segments
    polys: &Vec<(Vec<&Vec<Fr<G>>>, Option<usize>)>,
    srs_length: usize,
) -> Fr<G> {
    let mut res = Fr::<G>::zero();
    let mut xi_i = Fr::<G>::one();

    for (evals_tr, shifted) in polys.iter().filter(|(evals_tr, _)| evals_tr[0].len() > 0) {
        // transpose the evaluations
        let evals = (0..evals_tr[0].len())
            .map(|i| evals_tr.iter().map(|v| v[i]).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // iterating over the polynomial segments
        for eval in evals.iter() {
            let term = DensePolynomial::<Fr<G>>::eval_polynomial(eval, *r);

            res += &(xi_i * &term);
            xi_i *= xi;
        }

        if let Some(m) = shifted {
            // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
            let last_evals = if *m > evals.len() * srs_length {
                vec![Fr::<G>::zero(); evaluation_points.len()]
            } else {
                evals[evals.len() - 1].clone()
            };
            let shifted_evals: Vec<_> = evaluation_points
                .iter()
                .zip(last_evals.iter())
                .map(|(elm, f_elm)| elm.pow(&[(srs_length - (*m) % srs_length) as u64]) * f_elm)
                .collect();

            res += &(xi_i * &DensePolynomial::<Fr<G>>::eval_polynomial(&shifted_evals, *r));
            xi_i *= xi;
        }
    }
    res
}

impl<G: CommitmentCurve> SRS<G>
where
    G::ScalarField: CommitmentField,
{
    /// Commits a polynomial, potentially splitting the result in multiple commitments.
    pub fn commit(
        &self,
        plnm: &DensePolynomial<Fr<G>>,
        max: Option<usize>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (PolyComm<G>, PolyComm<Fr<G>>) {
        self.mask(self.commit_non_hiding(plnm, max), rng)
    }

    /// Turns a non-hiding polynomial commitment into a hidding polynomial commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with a random `w` per commitment.
    fn mask(
        &self,
        c: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (PolyComm<G>, PolyComm<Fr<G>>) {
        c.map(|g: G| {
            if g.is_zero() {
                // TODO: This leaks information when g is the identity!
                // We should change this so that we still mask in this case
                (g, Fr::<G>::zero())
            } else {
                let w = Fr::<G>::rand(rng);
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
        plnm: &DensePolynomial<Fr<G>>,
        max: Option<usize>,
    ) -> PolyComm<G> {
        let n = self.g.len();
        let p = plnm.coeffs.len();

        // committing all the segments without shifting
        let unshifted = if plnm.is_zero() {
            Vec::new()
        } else {
            (0..p / n + if p % n != 0 { 1 } else { 0 })
                .map(|i| {
                    VariableBaseMSM::multi_scalar_mul(
                        &self.g,
                        &plnm.coeffs[i * n..p]
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
                if plnm.is_zero() || start >= p {
                    Some(G::zero())
                } else if max % n == 0 {
                    None
                } else {
                    Some(
                        VariableBaseMSM::multi_scalar_mul(
                            &self.g[n - (max % n)..],
                            &plnm.coeffs[start..p]
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

    /// This function opens polynomial commitments in batch
    ///     plnms: batch of polynomials to open commitments for with, optionally, max degrees
    ///     elm: evaluation point vector to open the commitments at
    ///     polyscale: polynomial scaling factor for opening commitments in batch
    ///     evalscale: eval scaling factor for opening commitments in batch
    ///     oracle_params: parameters for the random oracle argument
    ///     RETURN: commitment opening proof
    pub fn open<EFqSponge, RNG>(
        &self,
        group_map: &G::Map,
        // TODO(mimoo): create a type for that entry
        plnms: Vec<(&DensePolynomial<Fr<G>>, Option<usize>, PolyComm<Fr<G>>)>, // vector of polynomial with optional degree bound and commitment randomness
        elm: &Vec<Fr<G>>,      // vector of evaluation points
        polyscale: Fr<G>,      // scaling factor for polynoms
        evalscale: Fr<G>,      // scaling factor for evaluation point powers
        mut sponge: EFqSponge, // sponge
        rng: &mut RNG,
    ) -> OpeningProof<G>
    where
        EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
        RNG: RngCore + CryptoRng,
    {
        let rounds = ceil_log2(self.g.len());
        let padded_length = 1 << rounds;

        // TODO: Trim this to the degree of the largest polynomial
        let padding = padded_length - self.g.len();
        let mut g = self.g.clone();
        g.extend(vec![G::zero(); padding]);

        // scale the polynoms in accumulator shifted, if bounded, to the end of SRS
        let (p, blinding_factor) = {
            let mut p = DensePolynomial::<Fr<G>>::zero();

            let mut omega = Fr::<G>::zero();
            let mut scale = Fr::<G>::one();

            // iterating over polynomials in the batch
            for (p_i, degree_bound, omegas) in plnms.iter().filter(|p| p.0.is_zero() == false) {
                let mut offset = 0;
                let mut j = 0;
                // iterating over chunks of the polynomial
                if let Some(m) = degree_bound {
                    assert!(p_i.coeffs.len() <= m + 1);
                    while offset < p_i.coeffs.len() {
                        let segment = DensePolynomial::<Fr<G>>::from_coefficients_slice(
                            &p_i.coeffs[offset..if offset + self.g.len() > p_i.coeffs.len() {
                                p_i.coeffs.len()
                            } else {
                                offset + self.g.len()
                            }],
                        );
                        // always mixing in the unshifted segments
                        p += &segment.scale(scale);
                        omega += &(omegas.unshifted[j] * scale);
                        j += 1;
                        scale *= &polyscale;
                        offset += self.g.len();
                        if offset > *m {
                            // mixing in the shifted segment since degree is bounded
                            p += &(segment.shiftr(self.g.len() - m % self.g.len()).scale(scale));
                            omega += &(omegas.shifted.unwrap() * scale);
                            scale *= &polyscale;
                        }
                    }
                } else {
                    assert!(omegas.shifted.is_none());
                    while offset < p_i.coeffs.len() {
                        let segment = DensePolynomial::<Fr<G>>::from_coefficients_slice(
                            &p_i.coeffs[offset..if offset + self.g.len() > p_i.coeffs.len() {
                                p_i.coeffs.len()
                            } else {
                                offset + self.g.len()
                            }],
                        );
                        // always mixing in the unshifted segments
                        p += &segment.scale(scale);
                        omega += &(omegas.unshifted[j] * scale);
                        j += 1;
                        scale *= &polyscale;
                        offset += self.g.len();
                    }
                }
                assert_eq!(j, omegas.unshifted.len());
            }
            (p, omega)
        };

        let rounds = ceil_log2(self.g.len());

        // b_j = sum_i r^i elm_i^j
        let b_init = {
            // randomise/scale the eval powers
            let mut scale = Fr::<G>::one();
            let mut res: Vec<Fr<G>> = (0..padded_length).map(|_| Fr::<G>::zero()).collect();
            for e in elm {
                for (i, t) in pows(padded_length, *e).iter().enumerate() {
                    res[i] += &(scale * t);
                }
                scale *= &evalscale;
            }
            res
        };

        let combined_inner_product = p
            .coeffs
            .iter()
            .zip(b_init.iter())
            .map(|(a, b)| *a * b)
            .fold(Fr::<G>::zero(), |acc, x| acc + x);

        sponge.absorb_fr(&[shift_scalar(combined_inner_product)]);

        let t = sponge.challenge_fq();
        let u: G = to_group(group_map, t);

        let mut a = p.coeffs;
        assert!(padded_length >= a.len());
        a.extend(vec![Fr::<G>::zero(); padded_length - a.len()]);

        let mut b = b_init.clone();

        let mut lr = vec![];

        let mut blinders = vec![];

        let mut chals = vec![];
        let mut chal_invs = vec![];

        for _ in 0..rounds {
            let n = g.len() / 2;
            let (g_lo, g_hi) = (g[0..n].to_vec(), g[n..].to_vec());
            let (a_lo, a_hi) = (&a[0..n], &a[n..]);
            let (b_lo, b_hi) = (&b[0..n], &b[n..]);

            let rand_l = Fr::<G>::rand(rng);
            let rand_r = Fr::<G>::rand(rng);

            let l = VariableBaseMSM::multi_scalar_mul(
                &[&g[0..n], &[self.h, u]].concat(),
                &[&a[n..], &[rand_l, inner_prod(a_hi, b_lo)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            let r = VariableBaseMSM::multi_scalar_mul(
                &[&g[n..], &[self.h, u]].concat(),
                &[&a[0..n], &[rand_r, inner_prod(a_lo, b_hi)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            lr.push((l, r));
            blinders.push((rand_l, rand_r));

            sponge.absorb_g(&[l]);
            sponge.absorb_g(&[r]);

            let u = squeeze_challenge(&self.endo_r, &mut sponge);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

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

            g = G::combine_one(&g_lo, &g_hi, u);
        }

        assert!(g.len() == 1);
        let a0 = a[0];
        let b0 = b[0];
        let g0 = g[0];

        let r_prime = blinders
            .iter()
            .zip(chals.iter().zip(chal_invs.iter()))
            .map(|((l, r), (u, u_inv))| ((*l) * u_inv) + &(*r * u))
            .fold(blinding_factor, |acc, x| acc + &x);

        let d = Fr::<G>::rand(rng);
        let r_delta = Fr::<G>::rand(rng);

        let delta = ((g0.into_projective() + &(u.mul(b0))).into_affine().mul(d)
            + &self.h.mul(r_delta))
            .into_affine();

        sponge.absorb_g(&[delta]);
        let c = ScalarChallenge(sponge.challenge()).to_field(&self.endo_r);

        let z1 = a0 * &c + &d;
        let z2 = c * &r_prime + &r_delta;

        OpeningProof {
            delta,
            lr,
            z1,
            z2,
            sg: g0,
        }
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
        batch: &mut Vec<(
            EFqSponge,
            Vec<Fr<G>>, // vector of evaluation points
            Fr<G>,      // scaling factor for polynomials
            Fr<G>,      // scaling factor for evaluation point powers
            Vec<(
                &PolyComm<G>,     // polycommitment
                Vec<&Vec<Fr<G>>>, // vector of evaluations
                Option<usize>,    // optional degree bound
            )>,
            &OpeningProof<G>, // batched opening proof
        )>,
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<Fq<G>, G, Fr<G>>,
        RNG: RngCore + CryptoRng,
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

        let max_rounds = ceil_log2(nonzero_length);

        let padded_length = 1 << max_rounds;

        // TODO: This will need adjusting
        let padding = padded_length - nonzero_length;
        let mut points = vec![self.h];
        points.extend(self.g.clone());
        points.extend(vec![G::zero(); padding]);

        let mut scalars = vec![Fr::<G>::zero(); padded_length + 1];
        assert_eq!(scalars.len(), points.len());

        // sample randomiser to scale the proofs with
        let rand_base = Fr::<G>::rand(rng);
        let sg_rand_base = Fr::<G>::rand(rng);

        let mut rand_base_i = Fr::<G>::one();
        let mut sg_rand_base_i = Fr::<G>::one();

        for (sponge, evaluation_points, xi, r, polys, opening) in batch.iter_mut() {
            // TODO: This computation is repeated in ProverProof::oracles
            let combined_inner_product0 = {
                let es: Vec<_> = polys
                    .iter()
                    .map(|(comm, evals, bound)| {
                        let bound: Option<usize> = (|| {
                            let b = (*bound)?;
                            let x = comm.shifted?;
                            if x.is_zero() {
                                None
                            } else {
                                Some(b)
                            }
                        })();
                        (evals.clone(), bound)
                    })
                    .collect();
                combined_inner_product::<G>(evaluation_points, xi, r, &es, self.g.len())
            };

            sponge.absorb_fr(&[shift_scalar(combined_inner_product0)]);

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
                let mut scale = Fr::<G>::one();
                let mut res = Fr::<G>::zero();
                for &e in evaluation_points.iter() {
                    let term = b_poly(&chal, e);
                    res += &(scale * &term);
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
            scalars.push(neg_rand_base_i * &opening.z1 - &sg_rand_base_i);

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
            scalars[0] -= &(rand_base_i * &opening.z2);

            // TERM
            // -rand_base_i * (z1 * b0 * U)
            scalars.push(neg_rand_base_i * &(opening.z1 * &b0));
            points.push(u);

            // TERM
            // rand_base_i c_i Q_i
            // = rand_base_i c_i
            //   (sum_j (chal_invs[j] L_j + chals[j] R_j) + P_prime)
            // where P_prime = combined commitment + combined_inner_product * U
            let rand_base_i_c_i = c * &rand_base_i;
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
                let mut xi_i = Fr::<G>::one();

                for (comm, _evals_tr, shifted) in polys.iter().filter(|x| x.0.unshifted.len() > 0) {
                    // iterating over the polynomial segments
                    for comm_ch in comm.unshifted.iter() {
                        scalars.push(rand_base_i_c_i * &xi_i);
                        points.push(*comm_ch);
                        xi_i *= *xi;
                    }

                    if let Some(_m) = shifted {
                        if let Some(comm_ch) = comm.shifted {
                            if comm_ch.is_zero() == false {
                                // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
                                scalars.push(rand_base_i_c_i * &xi_i);
                                points.push(comm_ch);
                                xi_i *= *xi;
                            }
                        }
                    }
                }
            };

            scalars.push(rand_base_i_c_i * &combined_inner_product0);
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

fn inner_prod<F: Field>(xs: &[F], ys: &[F]) -> F {
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

    #[test]
    fn test_log2() {
        let tests = [
            (1, 0),
            (2, 1),
            (3, 2),
            (9, 4),
            (15, 4),
            (15430, 14),
            (usize::MAX, 64),
        ];
        for (d, expected_res) in tests.iter() {
            let res = ceil_log2(*d);
            println!("ceil(log2({})) = {}, expected = {}", d, res, expected_res);
        }
    }
}
