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
use algebra::{
    curves::models::short_weierstrass_jacobian::GroupAffine as SWJAffine, AffineCurve, Field,
    FpParameters, One, PrimeField, ProjectiveCurve, SWModelParameters, SquareRootField,
    UniformRand, VariableBaseMSM, Zero,
};
use ff_fft::DensePolynomial;
use groupmap::{BWParameters, GroupMap};
use oracle::{sponge::ScalarChallenge, FqSponge};
use rand_core::RngCore;
use rayon::prelude::*;
use std::iter::Iterator;

//
// Aliases
//

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

//
// Polynomial Commitment
//

/// A polynomial commitment.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct PolyComm<C> {
    /// A polynomial commitment (potentially split in several commitments if needed)
    pub unshifted: Vec<C>,
    /// ?
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

impl<C: AffineCurve> PolyComm<C> {
    // TODO(mimoo): does this really belong in polycomm?
    pub fn multi_scalar_mul(com: &Vec<&PolyComm<C>>, elm: &Vec<C::ScalarField>) -> Self {
        assert_eq!(com.len(), elm.len());
        let shifted = {
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
        };
        let unshifted = {
            if com.len() == 0 || elm.len() == 0 {
                Vec::new()
            } else {
                let n = com.iter().map(|c| c.unshifted.len());
                let n = Iterator::max(n).expect("com is not empty");
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
        };

        PolyComm::<C> { shifted, unshifted }
    }
}

//
// Opening proof
//

#[derive(Clone, Debug)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct OpeningProof<G: AffineCurve> {
    /// vector of rounds of L & R commitments
    pub lr: Vec<(G, G)>,
    /// Schnorr opening R
    pub delta: G,
    /// Schnorr opening S.1
    pub z1: G::ScalarField,
    /// Schnorr opening S.2
    pub z2: G::ScalarField,
    /// ?? always g0
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
            algebra::fields::batch_inversion(&mut cs);
            cs
        };

        Challenges { chal, chal_inv }
    }
}

//
// Utils
//

/// Returns the product of all the field elements belonging to an iterator.
// TODO(mimoo): this should be inlined easily no?
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

    // TODO(mimoo): refactor as:
    /*
    let one = F::one();
    let mut x_exp = x; // x, x^2, x^4, x^8, ...
    let mut res = one;
    for chal in chals.iter().rev() {
        res *= one + chal * x_exp;
        x_exp = x_exp.square();
    }
    res
    */
}

/// ?
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

    // TODO(mimoo): refactor with
    /*
    let mut k = 0u;
    let mut pow = 1u;
    for i in 1..s_length {
        if pow == i {
            k += 1;
            pow *= 2;
        }
        s[i] = s[i - (pow / 2)] * chals[rounds - 1 - (k - 1)];
    }
    s
    */
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

//
// Sponge stuff
//

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

//
// CommitmentCurve stuff
//

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

//
// Helper
//

/// Computes the linearization of the evaluations of a (potentially split) polynomial.
/// Each given `poly` is associated to a matrix where the rows represent the number of evaluated points,
/// and the columns represent potential segments (if a polynomial was split in several parts).
/// Note that if one of the polynomial comes specified with a degree bound,
/// the evaluation for the last segment is potentially shifted to meet the proof.
pub fn combined_inner_product<G: CommitmentCurve>(
    evaluation_points: &[Fr<G>],
    // TODO(mimoo): is xi = x^(g.len()) ? (that would make sense)
    xi: &Fr<G>,
    r: &Fr<G>,
    // TODO(mimoo): needs a type that can get you evaluations or segments
    polys: &Vec<(Vec<&Vec<Fr<G>>>, Option<usize>)>,
    srs_length: usize,
) -> Fr<G> {
    // TODO(mimoo): assert the following
    /*
    for (evals, _) in polys {
        for eval in evals {
            assert!(evaluation_points.len() == eval.len());
        }
    }
    */

    let mut res = Fr::<G>::zero();
    let mut xi_i = Fr::<G>::one(); // TODO(mimoo): why don't we reset this between polys? Also what about a linear combination of polys?

    // TODO(mimoo): in what case would evals_tr[0].len() == 0 ?
    for (evals_tr, shifted) in polys.iter().filter(|(evals_tr, _)| evals_tr[0].len() > 0) {
        // transpose the evaluations
        // [a, b, c], [d, e, f], [g, h, i], [j, k, l] ->
        // [a, d, g, j], [b, e, h, k], [c, f, i, l]
        let evals = (0..evals_tr[0].len())
            .map(|i| evals_tr.iter().map(|v| v[i]).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // iterating over the polynomial segments
        // res =      a + xi b + xi^2 c +
        //       r   (d + xi e + xi^2 f) +
        //       r^2 (g + xi h + xi^2 i) +
        //       r^3 (j + xi k + xi^2 l)
        for eval in evals.iter() {
            let term = DensePolynomial::<Fr<G>>::eval_polynomial(eval, *r);

            res += &(xi_i * &term);

            xi_i *= xi;
        }

        // if an upperbound on the polynomial degree is set, make sure to shift the evaluation:
        if let Some(m) = shifted {
            let max_degree_possible = evals.len() * srs_length;
            // get the latest segment if we can bound it, otherwise create one with all zero evaluations
            let last_evals = if m > &max_degree_possible {
                vec![Fr::<G>::zero(); evaluation_points.len()]
            } else {
                evals[evals.len() - 1].clone()
            };

            // shift the evaluation with point^shift
            let shift = (srs_length - (m % srs_length)) as u64;
            let shifted_evals: Vec<_> = evaluation_points
                .iter()
                .zip(last_evals.iter())
                .map(|(elm, f_elm)| elm.pow(&[shift]) * f_elm)
                .collect();
            // TODO(mimoo):
            /*
            let mut shifted_evals = vec![];
            for (point, eval) in evaluation_points.into_iter().zip(last_evals) {
                let shifted_eval = point.pow(&[shift]) * &eval;
                shifted_evals.push(shifted_eval);
            }
            */

            // xi^i sum_j r^j elm_j^{N - m} f(elm_j)
            res += &(xi_i * &DensePolynomial::<Fr<G>>::eval_polynomial(&shifted_evals, *r));

            xi_i *= xi;
        }
    }
    res
}

//
// Core functions
//

impl<G: CommitmentCurve> SRS<G>
where
    G::ScalarField: CommitmentField,
{
    /// Commits a polynomial, potentially splitting the result in multiple commitments.
    // TODO: shouldn't a hidding commitment be of a different type? (e.g. NonHiddingPolyComm)
    pub fn commit(
        &self,
        plnm: &DensePolynomial<Fr<G>>,
        max: Option<usize>,
        // TODO: replace with (impl RngCore + CryptoRng)
        rng: &mut dyn RngCore,
    ) -> (PolyComm<G>, PolyComm<Fr<G>>) {
        self.mask(self.commit_non_hiding(plnm, max), rng)
    }

    /// Turns a non-hiding polynomial commitment into a hidding polynomial commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with a random `w` per commitment.
    fn mask(&self, c: PolyComm<G>, rng: &mut dyn RngCore) -> (PolyComm<G>, PolyComm<Fr<G>>) {
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
        // TODO: why return the randomness as a PolyComm? Why not a HiddenPolyComm struct instead? I get that it has the same fields but it's semtically different enough.
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
            // calculate if we need to split the polynomial in multiple commitments
            let mut num_commit = p / n;
            if p % n != 0 {
                num_commit += 1
            }

            (0..num_commit)
                .map(|i| {
                    let offset = i * n;
                    VariableBaseMSM::multi_scalar_mul(
                        &self.g,
                        // TODO: shouldn't it be until min(p, (i+1)*n)?
                        &plnm.coeffs[offset..p]
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
                // only create a shifted polynomial if it makes sense
                // (for the last split, and if its degree is smaller than n)
                let last_split_offset = max - (max % n); // offset of the last split
                if plnm.is_zero() {
                    // nothing to upper bound here
                    Some(G::zero())
                } else if last_split_offset >= p {
                    // TODO: create a test at the limit to exercise that path
                    // case 1 the number of components already establish the max degree
                    Some(G::zero())
                } else if max % n == 0 {
                    // a max degree cannot be enforced if max is a multiple of n
                    None
                } else {
                    let g = &self.g[n - (max % n)..];
                    // TODO: ..p] -> ..]
                    let coeffs: Vec<_> = plnm.coeffs[last_split_offset..p]
                        .iter()
                        .map(|s| s.into_repr())
                        .collect();
                    let commit = VariableBaseMSM::multi_scalar_mul(g, &coeffs).into_affine();
                    Some(commit)
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
    // TODO(mimoo): better function name + return a Result
    pub fn open<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>>(
        &self,
        // TODO(mimoo): shouldn't this be part of the SRS?
        group_map: &G::Map,
        // TODO(mimoo): create a type for that entry
        plnms: Vec<(&DensePolynomial<Fr<G>>, Option<usize>, PolyComm<Fr<G>>)>, // vector of polynomial with optional degree bound and commitment randomness
        elm: &Vec<Fr<G>>,      // vector of evaluation points
        polyscale: Fr<G>,      // scaling factor for polynomials
        evalscale: Fr<G>,      // scaling factor for evaluation point powers
        mut sponge: EFqSponge, // sponge
        rng: &mut dyn RngCore,
    ) -> OpeningProof<G> {
        // make number of rounds a power of 2
        let rounds = ceil_log2(self.g.len());
        let padded_length = 1 << rounds;

        // TODO: Trim this to the degree of the largest polynomial
        let padding = padded_length - self.g.len();
        let mut g = self.g.clone();
        g.extend(vec![G::zero(); padding]);
        // REMOVED:       let rounds = ceil_log2(self.g.len());
        assert!(rounds == ceil_log2(self.g.len()));

        // scale the polynomials in accumulator shifted, if bounded, to the end of SRS
        let (p, blinding_factor) = {
            let mut p = DensePolynomial::<Fr<G>>::zero();

            let mut omega = Fr::<G>::zero();
            let mut scale = Fr::<G>::one();

            // iterating over polynomials in the batch
            // TODO(mimoo): why are we iterating over zeros?? I don't think that's normal (what if there's a bunch of zero coefficient in a middle polynomial?)
            let non_zeros = plnms.iter().filter(|p| !p.0.is_zero());
            for (p_i, degree_bound, omegas) in non_zeros {
                let mut offset = 0;
                let mut j = 0;

                // iterating over chunks of the polynomial
                if let Some(m) = degree_bound {
                    assert!(p_i.coeffs.len() <= m + 1);
                } else {
                    assert!(omegas.shifted.is_none());
                }

                // TODO(mimoo): this code should do what the below code does, but write tests before uncommenting & replacing
                /*
                // split the polynomials into several ones (would be cool if DensePolynomial had that as a method thx to the Utils trait (that already extend it with scale and shiftr, also the trait should be called DensePolynomialExt no?))
                let splits = p_i
                    .coeffs
                    .chunks(self.g.len())
                    .map(DensePolynomial::<Fr<G>>::from_coefficients_slice);
                assert!(omegas.unshifted.len() == splits.len());
                let chunks = splits.zip(&omegas.unshifted);
                for (poly, &unshifted) in chunks {
                    p += &poly.scale(scale); // TODO(mimoo): skip 1?
                    omega += &(unshifted * scale);
                    scale *= &polyscale;
                }
                // perhaps for the last chunk use .last() on the iter?
                // for powers of scale, use iterator?
                */

                while offset < p_i.coeffs.len() {
                    let end = std::cmp::min(offset + self.g.len(), p_i.coeffs.len());
                    let segment =
                        DensePolynomial::<Fr<G>>::from_coefficients_slice(&p_i.coeffs[offset..end]);
                    // always mixing in the unshifted segments
                    p += &segment.scale(scale); // TODO(mimoo): skip 1?
                    omega += &(omegas.unshifted[j] * scale);
                    j += 1;
                    scale *= &polyscale;
                    offset += self.g.len();

                    // TODO(mimoo): shouldn't we make sure that this step only happens with the last split polynomial???
                    // TODO(mimoo): we really need to test that part
                    if let Some(m) = degree_bound {
                        if offset > *m {
                            // mixing in the shifted segment since degree is bounded
                            let unused = self.g.len() - (m % self.g.len());
                            let shifted = segment.shiftr(unused);
                            assert!(shifted.len() <= self.g.len());
                            p += &(shifted.scale(scale));
                            omega += &(omegas.shifted.unwrap() * scale);
                            scale *= &polyscale;
                        }
                    }
                }

                assert_eq!(j, omegas.unshifted.len());
            }
            (p, omega)
        };

        // b_j = sum_i r^i elm_i^j
        // a padded-length vector where each entry is the linear combination of powers of our elements `elm` (where powers of `u` or `evalscale` is used in place of a random linear combination)
        let b_init = {
            // randomise/scale the eval powers
            let mut scale = Fr::<G>::one();
            let mut res: Vec<Fr<G>> = vec![Fr::<G>::zero(); padded_length];
            for e in elm {
                for (i, t) in pows(padded_length, *e).iter().enumerate() {
                    res[i] += &(scale * t);
                }
                scale *= &evalscale;
            }
            res
        };

        // <coeffs, b_init>
        // TODO(mimoo): use the inner_prod function here (try that after test works)
        // let combined_inner_product = inner_prod(&p.coeffs, &b_init);
        let combined_inner_product = p
            .coeffs
            .iter()
            .zip(b_init.iter())
            .map(|(a, b)| *a * b)
            .fold(Fr::<G>::zero(), |acc, x| acc + x);

        // absorb(<coeffs, b_init>)
        sponge.absorb_fr(&[shift_scalar(combined_inner_product)]);

        // sample t and map it to a curve point
        let t = sponge.challenge_fq();
        let u: G = to_group(group_map, t);

        // pad coefficients to the SRS commit base (G_1, ..., G_N) length
        let mut a = p.coeffs;
        assert!(padded_length >= a.len());
        a.extend(vec![Fr::<G>::zero(); padded_length - a.len()]);

        // for each round, keep track of:
        let mut lr = vec![]; // keep track of (l, r) in each round
        let mut blinders = vec![]; // keep track of randomness (rand_l, rand_r)
        let mut chals = vec![]; // keep track of x in each round
        let mut chal_invs = vec![]; // keep track of x^-1 in each round

        // reduce in `rounds` rounds
        let mut b = b_init.clone();
        for _ in 0..rounds {
            // split vectors in half
            let n = g.len() / 2;
            let (g_lo, g_hi) = (g[0..n].to_vec(), g[n..].to_vec());
            let (a_lo, a_hi) = (&a[0..n], &a[n..]);
            let (b_lo, b_hi) = (&b[0..n], &b[n..]);

            // blinding factors
            let rand_l = Fr::<G>::rand(rng);
            let rand_r = Fr::<G>::rand(rng);

            // l = <a_hi, G_lo> + <rand_l, H> + <a_hi, b_lo>U
            let l = VariableBaseMSM::multi_scalar_mul(
                &[&g[0..n], &[self.h, u]].concat(),
                &[&a[n..], &[rand_l, inner_prod(a_hi, b_lo)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
            .into_affine();

            // r = <a_lo, G_hi> + <rand_r, H> + <a_lo, b_hi>U
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

            // absorb transcript
            sponge.absorb_g(&[l]);
            sponge.absorb_g(&[r]);

            // get challenge x and x^-1 for the round
            let u = squeeze_challenge(&self.endo_r, &mut sponge);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

            // a = u_inv * a_hi + a_lo
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

            // b = u * b_hi + b_lo
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

            // g = g_lo + u g_hi
            g = G::combine_one(&g_lo, &g_hi, u);
        }

        // TODO(mimoo): assert that a and b are also of length 1
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

        // delta = g0 + (d * (u * b0)) + r_delta * h
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
    // TODO(mimoo): need an easier to use interface here, probably a type for batch
    pub fn verify<EFqSponge: FqSponge<Fq<G>, G, Fr<G>>>(
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
        rng: &mut dyn RngCore,
    ) -> bool {
        // TODO(mimoo): why G_i and not G_0?
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
            // = sum_i xi^i evaluation_points[i]
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

            // TODO(mimoo): why shift?
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

            // ?
            let s = b_poly_coefficients(&chal);

            // ?
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

//
// Helpers
//

fn inner_prod<F: Field>(xs: &[F], ys: &[F]) -> F {
    let mut res = F::zero();
    for (&x, y) in xs.iter().zip(ys) {
        res += &(x * y);
    }
    res
}

pub trait Utils<F: Field> {
    /// This function "scales" (multiplies all the coefficients of) a polynomial with a scalar.
    fn scale(&self, elm: F) -> Self;
    /// Shifts all the coefficients to the right.
    fn shiftr(&self, size: usize) -> Self;
    /// `eval_polynomial(coeffs, x)` evaluates a polynomial given its coefficients `coeffs` and a point `x`.
    fn eval_polynomial(coeffs: &[F], x: F) -> F;
    /// This function evaluates polynomial in chunks.
    fn eval(&self, elm: F, size: usize) -> Vec<F>;
}

impl<F: Field> Utils<F> for DensePolynomial<F> {
    fn eval_polynomial(coeffs: &[F], x: F) -> F {
        // this uses https://en.wikipedia.org/wiki/Horner%27s_method
        let mut res = F::zero();
        for c in coeffs.iter().rev() {
            res *= &x;
            res += c;
        }
        res
    }

    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {
            *coeff *= &elm
        }
        result
    }

    fn shiftr(&self, size: usize) -> Self {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }

    fn eval(&self, elm: F, size: usize) -> Vec<F> {
        (0..self.coeffs.len())
            .step_by(size)
            .map(|i| {
                Self::from_coefficients_slice(
                    &self.coeffs[i..if i + size > self.coeffs.len() {
                        self.coeffs.len()
                    } else {
                        i + size
                    }],
                )
                .evaluate(elm)
            })
            .collect()
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srs::SRS;
    use algebra::pasta::{fp::Fp, vesta::Affine as VestaG};
    use array_init::array_init;
    use oracle::poseidon::PlonkSpongeConstants as SC;
    use oracle::{pasta::fq::params as spongeFqParams, sponge::DefaultFqSponge};
    use rand::{rngs::StdRng, SeedableRng};

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

    #[test]
    fn test_opening_proof() {
        // create two polynomials
        let coeffs: [Fp; 10] = array_init(|i| Fp::from(i as u32));
        let poly = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs);
        //        let bounded_poly = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs[..5]);

        // create an SRS
        let srs = SRS::<VestaG>::create(20);
        let rng = &mut StdRng::from_seed([0u8; 32]);

        // commit the two polynomials (and upperbound the second one)
        let commitment = srs.commit(&poly, None, rng);
        //        let upperbound = bounded_poly.degree() + 1;
        //        let bounded_commitment = srs.commit(&bounded_poly, Some(upperbound), rng);
        println!("{:?}", commitment);
        //        println!("{:?}", bounded_commitment);

        // create an aggregated opening proof
        let (u, v) = (Fp::rand(rng), Fp::rand(rng));
        let group_map = <VestaG as CommitmentCurve>::Map::setup();
        let sponge = DefaultFqSponge::<_, SC>::new(spongeFqParams());

        let polys = vec![
            (&poly, None, commitment.1),
            //            (&bounded_poly, Some(upperbound), bounded_commitment.1),
        ];
        let elm = vec![Fp::rand(rng), Fp::rand(rng)];
        let opening_proof = srs.open(&group_map, polys, &elm, v, u, sponge.clone(), rng);

        // evaluate the polynomials at these two points
        let poly1_evals = vec![poly.evaluate(elm[0]), poly.evaluate(elm[1])];
        //        let poly2_evals = vec![bounded_poly.evaluate(elm[0]), bounded_poly.evaluate(elm[1])];

        println!("{:?}", opening_proof);

        // verify the proof
        let mut batch: Vec<(
            _,
            Vec<Fr<VestaG>>, // vector of evaluation points
            Fr<VestaG>,      // scaling factor for polynomials
            Fr<VestaG>,      // scaling factor for evaluation point powers
            Vec<(
                &PolyComm<VestaG>,     // polycommitment
                Vec<&Vec<Fr<VestaG>>>, // vector of evaluations
                Option<usize>,         // optional degree bound
            )>,
            &OpeningProof<VestaG>, // batched opening proof
        )> = vec![(
            sponge,
            elm.clone(),
            v,
            u,
            vec![
                (&commitment.0, vec![&poly1_evals], None),
                //                (&bounded_commitment.0, vec![&poly2_evals], Some(upperbound)),
            ],
            &opening_proof,
        )];
        assert!(srs.verify(&group_map, &mut batch, rng));
    }
}
