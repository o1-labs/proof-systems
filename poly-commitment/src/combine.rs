//! Batch elliptic curve algorithms based on the batch-affine principle.
//!
//! The principle is the following:
//!
//! Usually, affine coordinates are not used because curve operations require
//! division, which is very inefficient. However, if one is performing a large
//! number of curve operations at the same time, then the inverses can be computed
//! efficiently using the *batch inversion algorithm* which allows you to compute
//! the inverses for an array of elements at a cost of 3 multiplications per element.
//!
//! With the reduced cost of inversion, in settings where you are computing many
//! parallel elliptic curve operations, it is actually cheaper to use affine coordinates.
//!
//! Most algorithms in this module take an argument `denominators: &mut Vec<F>` which
//! is a scratch array used for performing inversions. It is passed around to
//! avoid re-allocating such a scratch array within each algorithm.

use alloc::{vec, vec::Vec};
use ark_ec::{
    models::short_weierstrass::Affine as SWJAffine, short_weierstrass::SWCurveConfig,
    AdditiveGroup, AffineRepr, CurveGroup,
};
use ark_ff::{BitIteratorBE, Field, One, PrimeField, Zero};
use core::ops::AddAssign;
use itertools::Itertools;
use mina_poseidon::sponge::ScalarChallenge;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Elements below which a chunk is not worth splitting further: rayon
/// dispatch and batch-inversion amortization overhead dominate under this
/// size. Tuned on the `fold_regression` benchmark.
#[cfg(feature = "parallel")]
const MIN_CHUNK: usize = 128;

/// Split `n` elements into per-thread chunks: enough chunks to occupy the
/// rayon pool, but never chunks smaller than [`MIN_CHUNK`]. This is the
/// single level of parallelism in this module - all the batch helpers below
/// run serially within one chunk.
#[cfg(feature = "parallel")]
fn chunk_size(n: usize) -> usize {
    let num_chunks = (n / MIN_CHUNK).clamp(1, 2 * rayon::current_num_threads());
    n.div_ceil(num_chunks).max(1)
}

#[cfg(not(feature = "parallel"))]
const fn chunk_size(n: usize) -> usize {
    if n == 0 {
        1
    } else {
        n
    }
}

/// Serial Montgomery batch inversion: replaces every non-zero element with
/// its inverse and leaves zeros untouched, at a cost of three
/// multiplications per element and a single field inversion.
///
/// Semantically identical to `ark_ff::batch_inversion`, but always serial:
/// ark's version parallelizes internally under its `parallel` feature with no
/// serial escape hatch, and every call in this module already runs inside a
/// parallel chunk, where the extra fork/join per call is pure overhead.
fn serial_batch_inversion<F: Field>(v: &mut [F]) {
    // Forward pass: prefix products of the non-zero elements.
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = F::one();
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp *= *f;
        prod.push(tmp);
    }

    // Invert the total product (non-zero: it is a product of non-zeros).
    let mut inv = tmp.inverse().expect("product of non-zero field elements");

    // Backward pass: peel one factor off per element to recover each inverse
    // from the prefix product of the elements before it.
    for (f, s) in v.iter_mut().rev().filter(|f| !f.is_zero()).zip(
        prod.into_iter()
            .rev()
            .skip(1)
            .chain(core::iter::once(F::one())),
    ) {
        let new_inv = inv * *f;
        *f = inv * s;
        inv = new_inv;
    }
}

fn add_pairs_in_place<P: SWCurveConfig>(pairs: &mut Vec<SWJAffine<P>>) {
    let len = if pairs.len().is_multiple_of(2) {
        pairs.len()
    } else {
        pairs.len() - 1
    };
    let mut denominators = pairs
        .as_chunks_mut::<2>()
        .0
        .iter()
        .map(|p| {
            if p[0].x == p[1].x {
                if p[1].y.is_zero() {
                    P::BaseField::one()
                } else {
                    p[1].y.double()
                }
            } else {
                p[0].x - p[1].x
            }
        })
        .collect::<Vec<_>>();

    serial_batch_inversion::<P::BaseField>(&mut denominators);

    for (i, d) in (0..len).step_by(2).zip(denominators.iter()) {
        let j = i / 2;
        if pairs[i + 1].is_zero() {
            pairs[j] = pairs[i];
        } else if pairs[i].is_zero() {
            pairs[j] = pairs[i + 1];
        } else if pairs[i + 1].x == pairs[i].x
            && (pairs[i + 1].y != pairs[i].y || pairs[i + 1].y.is_zero())
        {
            pairs[j] = SWJAffine::<P>::zero();
        } else if pairs[i + 1].x == pairs[i].x && pairs[i + 1].y == pairs[i].y {
            let sq = pairs[i].x.square();
            let s = (sq.double() + sq + P::COEFF_A) * d;
            let x = s.square() - pairs[i].x.double();
            let y = -pairs[i].y - (s * (x - pairs[i].x));
            pairs[j].x = x;
            pairs[j].y = y;
        } else {
            let s = (pairs[i].y - pairs[i + 1].y) * d;
            let x = s.square() - pairs[i].x - pairs[i + 1].x;
            let y = -pairs[i].y - (s * (x - pairs[i].x));
            pairs[j].x = x;
            pairs[j].y = y;
        }
    }

    let len = pairs.len();
    if len % 2 == 1 {
        pairs[len / 2] = pairs[len - 1];
        pairs.truncate(len / 2 + 1);
    } else {
        pairs.truncate(len / 2);
    }
}

/// Given arrays of curve points `v0` and `v1` do `v0[i] += v1[i]` for each i,
/// assuming that for each `i`, `v0[i].x != v1[i].x` so we can use the ordinary
/// addition formula and don't have to handle the edge cases of doubling and
/// hitting the point at infinity.
#[hotpath::measure]
fn batch_add_assign_no_branch<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    v0: &mut [SWJAffine<P>],
    v1: &[SWJAffine<P>],
) {
    hotpath::measure_block!("nobranch::denominators", {
        denominators
            .iter_mut()
            .zip(v0.iter())
            .zip(v1.iter())
            .for_each(|((denom, p0), p1)| {
                *denom = p0.x - p1.x;
            });
    });

    hotpath::measure_block!("nobranch::inversion", {
        serial_batch_inversion::<P::BaseField>(denominators);
    });

    hotpath::measure_block!("nobranch::add_formula", {
        denominators
            .iter()
            .zip(v0.iter_mut())
            .zip(v1.iter())
            .for_each(|((d, p0), p1)| {
                let s = (p0.y - p1.y) * d;
                let x = s.square() - p0.x - p1.x;
                let y = -p0.y - (s * (x - p0.x));
                p0.x = x;
                p0.y = y;
            });
    });
}

/// Given arrays of curve points `v0` and `v1` do `v0[i] += v1[i]` for each i.
#[hotpath::measure]
pub fn batch_add_assign<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    v0: &mut [SWJAffine<P>],
    v1: &[SWJAffine<P>],
) {
    hotpath::measure_block!("branch::denominators", {
        denominators
            .iter_mut()
            .zip(v0.iter())
            .zip(v1.iter())
            .for_each(|((denom, p0), p1)| {
                let d = if p0.x == p1.x {
                    if p1.y.is_zero() {
                        P::BaseField::one()
                    } else {
                        p1.y.double()
                    }
                } else {
                    p0.x - p1.x
                };
                *denom = d;
            });
    });

    hotpath::measure_block!("branch::inversion", {
        serial_batch_inversion::<P::BaseField>(denominators);
    });

    hotpath::measure_block!("branch::add_formula", {
        denominators
            .iter()
            .zip(v0.iter_mut())
            .zip(v1.iter())
            .for_each(|((d, p0), p1)| {
                if p1.is_zero() {
                } else if p0.is_zero() {
                    *p0 = *p1;
                } else if p1.x == p0.x && (p1.y != p0.y || p1.y == P::BaseField::zero()) {
                    *p0 = SWJAffine::<P>::zero();
                } else if p1.x == p0.x && p1.y == p0.y {
                    let sq = p0.x.square();
                    let s = (sq.double() + sq + P::COEFF_A) * d;
                    let x = s.square() - p0.x.double();
                    let y = -p0.y - (s * (x - p0.x));
                    p0.x = x;
                    p0.y = y;
                } else {
                    let s = (p0.y - p1.y) * d;
                    let x = s.square() - p0.x - p1.x;
                    let y = -p0.y - (s * (x - p0.x));
                    p0.x = x;
                    p0.y = y;
                }
            });
    });
}

fn affine_window_combine_base<P: SWCurveConfig>(
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    x1: P::ScalarField,
    x2: P::ScalarField,
) -> Vec<SWJAffine<P>> {
    let g1g2 = {
        let mut v: Vec<_> = (0..2 * g1.len())
            .map(|i| {
                let j = i / 2;
                if i % 2 == 0 {
                    g1[j]
                } else {
                    g2[j]
                }
            })
            .collect();
        add_pairs_in_place(&mut v);
        v
    };
    assert_eq!(g1g2.len(), g1.len());

    let windows1 = BitIteratorBE::new(x1.into_bigint()).tuples();
    let windows2 = BitIteratorBE::new(x2.into_bigint()).tuples();

    let mut points = vec![SWJAffine::<P>::zero(); g1.len()];

    let mut denominators = vec![P::BaseField::zero(); g1.len()];

    let [g01_00, g10_00, g11_00, g00_01, g01_01, g10_01, g11_01, g00_10, g01_10, g10_10, g11_10, g00_11, g01_11, g10_11, g11_11] =
        affine_shamir_window_table(&mut denominators, g1, g2);

    for ((hi_1, lo_1), (hi_2, lo_2)) in windows1.zip(windows2) {
        // double in place
        for _ in 0..2 {
            for i in 0..g1.len() {
                denominators[i] = points[i].y.double();
            }
            serial_batch_inversion::<P::BaseField>(&mut denominators);

            // TODO: Use less memory
            for i in 0..g1.len() {
                let d = denominators[i];
                let sq = points[i].x.square();
                let s = (sq.double() + sq + P::COEFF_A) * d;
                let x = s.square() - points[i].x.double();
                let y = -points[i].y - (s * (x - points[i].x));
                points[i].x = x;
                points[i].y = y;
            }
        }

        match ((hi_1, lo_1), (hi_2, lo_2)) {
            ((false, false), (false, false)) => (),
            ((false, true), (false, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_00);
            }
            ((true, false), (false, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_00);
            }
            ((true, true), (false, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_00);
            }

            ((false, false), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g00_01);
            }
            ((false, true), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_01);
            }
            ((true, false), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_01);
            }
            ((true, true), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_01);
            }

            ((false, false), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g00_10);
            }
            ((false, true), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_10);
            }
            ((true, false), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_10);
            }
            ((true, true), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_10);
            }

            ((false, false), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g00_11);
            }
            ((false, true), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_11);
            }
            ((true, false), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_11);
            }
            ((true, true), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_11);
            }
        }
    }
    points
}

#[hotpath::measure]
fn batch_endo_in_place<P: SWCurveConfig>(endo_coeff: P::BaseField, ps: &mut [SWJAffine<P>]) {
    for p in ps.iter_mut() {
        p.x *= endo_coeff;
    }
}

#[hotpath::measure]
fn batch_negate_in_place<P: SWCurveConfig>(ps: &mut [SWJAffine<P>]) {
    for p in ps.iter_mut() {
        p.y = -p.y;
    }
}

/// Uses a batch version of Algorithm 1 of
/// <https://eprint.iacr.org/2019/1021.pdf> (on page 19) to compute `g1 +
/// g2.scale(chal.to_field(endo_coeff))`
#[hotpath::measure]
fn affine_window_combine_one_endo_base<P: SWCurveConfig>(
    endo_coeff: P::BaseField,
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    chal: &ScalarChallenge<P::ScalarField>,
) -> Vec<SWJAffine<P>> {
    fn assign<A: Copy>(dst: &mut [A], src: &[A]) {
        let n = dst.len();
        dst[..n].clone_from_slice(&src[..n]);
    }

    const fn get_bit(limbs_lsb: &[u64], i: u64) -> u64 {
        let limb = i / 64;
        let j = i % 64;
        (limbs_lsb[limb as usize] >> j) & 1
    }

    let rep = chal.inner().into_bigint();
    let r = rep.as_ref();

    let mut denominators = vec![P::BaseField::zero(); g1.len()];

    // Each ladder iteration adds one of only four loop-invariant vectors:
    // g2, -g2, phi(g2), or -phi(g2) (negation touches y, the endomorphism
    // touches x, so the two commute). Precompute all four once instead of
    // rebuilding the selected variant from g2 on every iteration.
    let (g2_endo, g2_neg, g2_endo_neg) = hotpath::measure_block!("endo::precompute", {
        let mut g2_endo = g2.to_vec();
        batch_endo_in_place(endo_coeff, &mut g2_endo);
        let mut g2_neg = g2.to_vec();
        batch_negate_in_place(&mut g2_neg);
        let mut g2_endo_neg = g2_endo.clone();
        batch_negate_in_place(&mut g2_endo_neg);
        (g2_endo, g2_neg, g2_endo_neg)
    });

    // acc = 2 (phi(g2) + g2)
    let mut points = g2_endo.clone();
    hotpath::measure_block!("endo::setup", {
        batch_add_assign_no_branch(&mut denominators, &mut points, g2);
        batch_double_in_place(&mut denominators, &mut points);
    });

    let mut tmp_acc = g2.to_vec();
    hotpath::measure_block!("endo::ladder", {
        for i in (0..(128 / 2)).rev() {
            // tmp = acc
            assign(&mut tmp_acc, &points);

            // s = (-1)^(1 - r_2i) * phi^(r_2i1) (g2)
            let s: &[SWJAffine<P>] = match (get_bit(r, 2 * i + 1), get_bit(r, 2 * i)) {
                (0, 1) => g2,
                (0, _) => &g2_neg,
                (_, 1) => &g2_endo,
                (_, _) => &g2_endo_neg,
            };

            // acc = (acc + s) + acc
            batch_add_assign_no_branch(&mut denominators, &mut points, s);
            batch_add_assign_no_branch(&mut denominators, &mut points, &tmp_acc);
        }
    });
    // acc += g1
    batch_add_assign(&mut denominators, &mut points, g1);
    points
}

/// Double an array of curve points in-place.
#[hotpath::measure]
fn batch_double_in_place<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    points: &mut [SWJAffine<P>],
) {
    denominators
        .iter_mut()
        .zip(points.iter())
        .for_each(|(d, p)| {
            *d = p.y.double();
        });
    serial_batch_inversion::<P::BaseField>(denominators);

    // TODO: Use less memory
    denominators
        .iter()
        .zip(points.iter_mut())
        .for_each(|(d, p)| {
            let sq = p.x.square();
            let s = (sq.double() + sq + P::COEFF_A) * d;
            let x = s.square() - p.x.double();
            let y = -p.y - (s * (x - p.x));
            p.x = x;
            p.y = y;
        });
}

fn affine_window_combine_one_base<P: SWCurveConfig>(
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    x2: P::ScalarField,
) -> Vec<SWJAffine<P>> {
    let windows2 = BitIteratorBE::new(x2.into_bigint()).tuples();

    let mut points = vec![SWJAffine::<P>::zero(); g1.len()];

    let mut denominators = vec![P::BaseField::zero(); g1.len()];

    let [g01, g10, g11] = affine_shamir_window_table_one(&mut denominators, g2);

    for (hi_2, lo_2) in windows2 {
        // double in place
        for _ in 0..2 {
            for i in 0..g1.len() {
                denominators[i] = points[i].y.double();
            }
            serial_batch_inversion::<P::BaseField>(&mut denominators);

            // TODO: Use less memory
            for i in 0..g1.len() {
                let d = denominators[i];
                let sq = points[i].x.square();
                let s = (sq.double() + sq + P::COEFF_A) * d;
                let x = s.square() - points[i].x.double();
                let y = -points[i].y - (s * (x - points[i].x));
                points[i].x = x;
                points[i].y = y;
            }
        }

        match (hi_2, lo_2) {
            (false, false) => (),
            (false, true) => batch_add_assign(&mut denominators, &mut points, &g01),
            (true, false) => batch_add_assign(&mut denominators, &mut points, &g10),
            (true, true) => {
                batch_add_assign(&mut denominators, &mut points, &g11);
            }
        }
    }

    batch_add_assign(&mut denominators, &mut points, g1);

    points
}

pub fn affine_window_combine<P: SWCurveConfig>(
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    x1: P::ScalarField,
    x2: P::ScalarField,
) -> Vec<SWJAffine<P>> {
    let chunk_size = chunk_size(g1.len());
    let b: Vec<_> = g1.chunks(chunk_size).zip(g2.chunks(chunk_size)).collect();
    let v: Vec<_> = o1_utils::cfg_into_iter!(b)
        .map(|(v1, v2)| affine_window_combine_base(v1, v2, x1, x2))
        .collect();
    v.concat()
}

/// Given vectors of curve points `g1` and `g2`, compute a vector whose ith
/// entry is `g1[i] + g2[i].scale(chal.to_field(endo_coeff))`
///
/// Internally, it uses the curve endomorphism to speed up this operation.
pub fn affine_window_combine_one_endo<P: SWCurveConfig>(
    endo_coeff: P::BaseField,
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    chal: &ScalarChallenge<P::ScalarField>,
) -> Vec<SWJAffine<P>> {
    let chunk_size = chunk_size(g1.len());
    let b: Vec<_> = g1.chunks(chunk_size).zip(g2.chunks(chunk_size)).collect();
    let v: Vec<_> = o1_utils::cfg_into_iter!(b)
        .map(|(v1, v2)| affine_window_combine_one_endo_base(endo_coeff, v1, v2, chal))
        .collect();
    v.concat()
}
pub fn affine_window_combine_one<P: SWCurveConfig>(
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    x2: P::ScalarField,
) -> Vec<SWJAffine<P>> {
    let chunk_size = chunk_size(g1.len());
    let b: Vec<_> = g1.chunks(chunk_size).zip(g2.chunks(chunk_size)).collect();
    let v: Vec<_> = o1_utils::cfg_into_iter!(b)
        .map(|(v1, v2)| affine_window_combine_one_base(v1, v2, x2))
        .collect();
    v.concat()
}

pub fn window_combine<G: AffineRepr>(
    g_lo: &[G],
    g_hi: &[G],
    x_lo: G::ScalarField,
    x_hi: G::ScalarField,
) -> Vec<G> {
    let mut g_proj: Vec<G::Group> = {
        let pairs: Vec<_> = g_lo.iter().zip(g_hi).collect();
        o1_utils::cfg_into_iter!(pairs)
            .map(|(lo, hi)| window_shamir::<G>(x_lo, *lo, x_hi, *hi))
            .collect()
    };
    G::Group::normalize_batch(g_proj.as_mut_slice())
}

pub fn affine_shamir_window_table<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
) -> [Vec<SWJAffine<P>>; 15] {
    fn assign<A: Copy>(dst: &mut [A], src: &[A]) {
        let n = dst.len();
        dst[..n].clone_from_slice(&src[..n]);
    }

    let n = g1.len();

    let mut res: [Vec<_>; 15] = [
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
    ];

    let [g01_00, g10_00, g11_00, g00_01, g01_01, g10_01, g11_01, g00_10, g01_10, g10_10, g11_10, g00_11, g01_11, g10_11, g11_11] =
        &mut res;

    assign(g01_00, g1);

    assign(g10_00, g1);
    batch_add_assign(denominators, g10_00, g1);

    assign(g11_00, g10_00);
    batch_add_assign(denominators, g11_00, g1);

    assign(g00_01, g2);

    assign(g01_01, g00_01);
    batch_add_assign(denominators, g01_01, g1);

    assign(g10_01, g01_01);
    batch_add_assign(denominators, g10_01, g1);

    assign(g11_01, g10_01);
    batch_add_assign(denominators, g11_01, g1);

    assign(g00_10, g00_01);
    batch_add_assign(denominators, g00_10, g2);

    assign(g01_10, g00_10);
    batch_add_assign(denominators, g01_10, g1);

    assign(g10_10, g01_10);
    batch_add_assign(denominators, g10_10, g1);

    assign(g11_10, g10_10);
    batch_add_assign(denominators, g11_10, g1);

    assign(g00_11, g00_10);
    batch_add_assign(denominators, g00_11, g2);

    assign(g01_11, g00_11);
    batch_add_assign(denominators, g01_11, g1);

    assign(g10_11, g01_11);
    batch_add_assign(denominators, g10_11, g1);

    assign(g11_11, g10_11);
    batch_add_assign(denominators, g11_11, g1);

    res
}

pub fn affine_shamir_window_table_one<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    g1: &[SWJAffine<P>],
) -> [Vec<SWJAffine<P>>; 3] {
    fn assign<A: Copy>(dst: &mut [A], src: &[A]) {
        let n = dst.len();
        dst[..n].clone_from_slice(&src[..n]);
    }

    let n = g1.len();

    let mut res: [Vec<_>; 3] = [
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
    ];

    let [g01, g10, g11] = &mut res;

    assign(g01, g1);

    assign(g10, g1);
    batch_add_assign(denominators, g10, g1);

    assign(g11, g10);
    batch_add_assign(denominators, g11, g1);

    res
}

fn window_shamir<G: AffineRepr>(x1: G::ScalarField, g1: G, x2: G::ScalarField, g2: G) -> G::Group {
    let [_g00_00, g01_00, g10_00, g11_00, g00_01, g01_01, g10_01, g11_01, g00_10, g01_10, g10_10, g11_10, g00_11, g01_11, g10_11, g11_11] =
        shamir_window_table(g1, g2);

    let windows1 = BitIteratorBE::new(x1.into_bigint()).tuples();
    let windows2 = BitIteratorBE::new(x2.into_bigint()).tuples();

    let mut res = G::Group::zero();

    for ((hi_1, lo_1), (hi_2, lo_2)) in windows1.zip(windows2) {
        res.double_in_place();
        res.double_in_place();
        match ((hi_1, lo_1), (hi_2, lo_2)) {
            ((false, false), (false, false)) => (),
            ((false, true), (false, false)) => res.add_assign(&g01_00),
            ((true, false), (false, false)) => res.add_assign(&g10_00),
            ((true, true), (false, false)) => res.add_assign(&g11_00),

            ((false, false), (false, true)) => res.add_assign(&g00_01),
            ((false, true), (false, true)) => res.add_assign(&g01_01),
            ((true, false), (false, true)) => res.add_assign(&g10_01),
            ((true, true), (false, true)) => res.add_assign(&g11_01),

            ((false, false), (true, false)) => res.add_assign(&g00_10),
            ((false, true), (true, false)) => res.add_assign(&g01_10),
            ((true, false), (true, false)) => res.add_assign(&g10_10),
            ((true, true), (true, false)) => res.add_assign(&g11_10),

            ((false, false), (true, true)) => res.add_assign(&g00_11),
            ((false, true), (true, true)) => res.add_assign(&g01_11),
            ((true, false), (true, true)) => res.add_assign(&g10_11),
            ((true, true), (true, true)) => res.add_assign(&g11_11),
        }
    }

    res
}

pub fn shamir_window_table<G: AffineRepr>(g1: G, g2: G) -> [G; 16] {
    let g00_00 = G::generator().into_group();
    let g01_00 = g1.into_group();
    let g10_00 = {
        let mut g = g01_00;
        g.add_assign(&g1);
        g
    };
    let g11_00 = {
        let mut g = g10_00;
        g.add_assign(&g1);
        g
    };

    let g00_01 = g2.into_group();
    let g01_01 = {
        let mut g = g00_01;
        g.add_assign(&g1);
        g
    };
    let g10_01 = {
        let mut g = g01_01;
        g.add_assign(&g1);
        g
    };
    let g11_01 = {
        let mut g = g10_01;
        g.add_assign(&g1);
        g
    };

    let g00_10 = {
        let mut g = g00_01;
        g.add_assign(&g2);
        g
    };
    let g01_10 = {
        let mut g = g00_10;
        g.add_assign(&g1);
        g
    };
    let g10_10 = {
        let mut g = g01_10;
        g.add_assign(&g1);
        g
    };
    let g11_10 = {
        let mut g = g10_10;
        g.add_assign(&g1);
        g
    };
    let g00_11 = {
        let mut g = g00_10;
        g.add_assign(&g2);
        g
    };
    let g01_11 = {
        let mut g = g00_11;
        g.add_assign(&g1);
        g
    };
    let g10_11 = {
        let mut g = g01_11;
        g.add_assign(&g1);
        g
    };
    let g11_11 = {
        let mut g = g10_11;
        g.add_assign(&g1);
        g
    };

    let mut v = vec![
        g00_00, g01_00, g10_00, g11_00, g00_01, g01_01, g10_01, g11_01, g00_10, g01_10, g10_10,
        g11_10, g00_11, g01_11, g10_11, g11_11,
    ];
    let v: Vec<_> = G::Group::normalize_batch(v.as_mut_slice());
    [
        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13],
        v[14], v[15],
    ]
}
