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
//! is a scratch array used for performing inversions. It is passed around to avoid re-allocating
//! such a scratch array within each algorithm.

use ark_ec::{
    models::short_weierstrass::Affine as SWJAffine, short_weierstrass::SWCurveConfig, AffineRepr,
    CurveGroup, Group,
};
use ark_ff::{BitIteratorBE, Field, One, PrimeField, Zero};
use itertools::Itertools;
use mina_poseidon::sponge::ScalarChallenge;
use rayon::prelude::*;
use std::ops::AddAssign;

fn add_pairs_in_place<P: SWCurveConfig>(pairs: &mut Vec<SWJAffine<P>>) {
    let len = if pairs.len() % 2 == 0 {
        pairs.len()
    } else {
        pairs.len() - 1
    };
    let mut denominators = pairs
        .chunks_exact_mut(2)
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

    ark_ff::batch_inversion::<P::BaseField>(&mut denominators);

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
fn batch_add_assign_no_branch<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    v0: &mut [SWJAffine<P>],
    v1: &[SWJAffine<P>],
) {
    denominators
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, denom)| {
            let p0 = v0[i];
            let p1 = v1[i];
            let d = p0.x - p1.x;
            *denom = d;
        });

    ark_ff::batch_inversion::<P::BaseField>(denominators);

    denominators
        .par_iter()
        .zip(v0.par_iter_mut())
        .zip(v1.par_iter())
        .for_each(|((d, p0), p1)| {
            let s = (p0.y - p1.y) * d;
            let x = s.square() - p0.x - p1.x;
            let y = -p0.y - (s * (x - p0.x));
            p0.x = x;
            p0.y = y;
        });
}

/// Given arrays of curve points `v0` and `v1` do `v0[i] += v1[i]` for each i.
pub fn batch_add_assign<P: SWCurveConfig>(
    denominators: &mut [P::BaseField],
    v0: &mut [SWJAffine<P>],
    v1: &[SWJAffine<P>],
) {
    denominators
        .par_iter_mut()
        .zip(v0.par_iter())
        .zip(v1.par_iter())
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

    ark_ff::batch_inversion::<P::BaseField>(denominators);

    denominators
        .par_iter()
        .zip(v0.par_iter_mut())
        .zip(v1.par_iter())
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
    assert!(g1g2.len() == g1.len());

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
            ark_ff::batch_inversion::<P::BaseField>(&mut denominators);

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
                batch_add_assign(&mut denominators, &mut points, &g01_00)
            }
            ((true, false), (false, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_00)
            }
            ((true, true), (false, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_00)
            }

            ((false, false), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g00_01)
            }
            ((false, true), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_01)
            }
            ((true, false), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_01)
            }
            ((true, true), (false, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_01)
            }

            ((false, false), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g00_10)
            }
            ((false, true), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_10)
            }
            ((true, false), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_10)
            }
            ((true, true), (true, false)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_10)
            }

            ((false, false), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g00_11)
            }
            ((false, true), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g01_11)
            }
            ((true, false), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g10_11)
            }
            ((true, true), (true, true)) => {
                batch_add_assign(&mut denominators, &mut points, &g11_11)
            }
        }
    }
    points
}

fn batch_endo_in_place<P: SWCurveConfig>(endo_coeff: P::BaseField, ps: &mut [SWJAffine<P>]) {
    ps.par_iter_mut().for_each(|p| p.x *= endo_coeff);
}

fn batch_negate_in_place<P: SWCurveConfig>(ps: &mut [SWJAffine<P>]) {
    ps.par_iter_mut().for_each(|p| {
        p.y = -p.y;
    });
}

/// Uses a batch version of Algorithm 1 of <https://eprint.iacr.org/2019/1021.pdf> (on page 19) to
/// compute `g1 + g2.scale(chal.to_field(endo_coeff))`
fn affine_window_combine_one_endo_base<P: SWCurveConfig>(
    endo_coeff: P::BaseField,
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    chal: ScalarChallenge<P::ScalarField>,
) -> Vec<SWJAffine<P>> {
    fn assign<A: Copy>(dst: &mut [A], src: &[A]) {
        let n = dst.len();
        dst[..n].clone_from_slice(&src[..n]);
    }

    fn get_bit(limbs_lsb: &[u64], i: u64) -> u64 {
        let limb = i / 64;
        let j = i % 64;
        (limbs_lsb[limb as usize] >> j) & 1
    }

    let rep = chal.0.into_bigint();
    let r = rep.as_ref();

    let mut denominators = vec![P::BaseField::zero(); g1.len()];
    // acc = 2 (phi(g2) + g2)
    let mut points = g2.to_vec();
    batch_endo_in_place(endo_coeff, &mut points);
    batch_add_assign_no_branch(&mut denominators, &mut points, g2);
    batch_double_in_place(&mut denominators, &mut points);

    let mut tmp_s = g2.to_vec();
    let mut tmp_acc = g2.to_vec();
    for i in (0..(128 / 2)).rev() {
        // s = g2
        assign(&mut tmp_s, g2);
        // tmp = acc
        assign(&mut tmp_acc, &points);

        let r_2i = get_bit(r, 2 * i);
        if r_2i == 0 {
            batch_negate_in_place(&mut tmp_s);
        }
        if get_bit(r, 2 * i + 1) == 1 {
            batch_endo_in_place(endo_coeff, &mut tmp_s);
        }

        // acc = (acc + s) + acc
        batch_add_assign_no_branch(&mut denominators, &mut points, &tmp_s);
        batch_add_assign_no_branch(&mut denominators, &mut points, &tmp_acc);
    }
    // acc += g1
    batch_add_assign(&mut denominators, &mut points, g1);
    points
}

/// Double an array of curve points in-place.
fn batch_double_in_place<P: SWCurveConfig>(
    denominators: &mut Vec<P::BaseField>,
    points: &mut [SWJAffine<P>],
) {
    denominators
        .par_iter_mut()
        .zip(points.par_iter())
        .for_each(|(d, p)| {
            *d = p.y.double();
        });
    ark_ff::batch_inversion::<P::BaseField>(denominators);

    // TODO: Use less memory
    denominators
        .par_iter()
        .zip(points.par_iter_mut())
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
            ark_ff::batch_inversion::<P::BaseField>(&mut denominators);

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
            (true, true) => batch_add_assign(&mut denominators, &mut points, &g11),
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
    const CHUNK_SIZE: usize = 10_000;
    let b: Vec<_> = g1.chunks(CHUNK_SIZE).zip(g2.chunks(CHUNK_SIZE)).collect();
    let v: Vec<_> = b
        .into_par_iter()
        .map(|(v1, v2)| affine_window_combine_base(v1, v2, x1, x2))
        .collect();
    v.concat()
}

/// Given vectors of curve points `g1` and `g2`, compute a vector whose ith entry is
/// `g1[i] + g2[i].scale(chal.to_field(endo_coeff))`
///
/// Internally, it uses the curve endomorphism to speed up this operation.
pub fn affine_window_combine_one_endo<P: SWCurveConfig>(
    endo_coeff: P::BaseField,
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    chal: ScalarChallenge<P::ScalarField>,
) -> Vec<SWJAffine<P>> {
    const CHUNK_SIZE: usize = 4096;
    let b: Vec<_> = g1.chunks(CHUNK_SIZE).zip(g2.chunks(CHUNK_SIZE)).collect();
    let v: Vec<_> = b
        .into_par_iter()
        .map(|(v1, v2)| affine_window_combine_one_endo_base(endo_coeff, v1, v2, chal.clone()))
        .collect();
    v.concat()
}
pub fn affine_window_combine_one<P: SWCurveConfig>(
    g1: &[SWJAffine<P>],
    g2: &[SWJAffine<P>],
    x2: P::ScalarField,
) -> Vec<SWJAffine<P>> {
    const CHUNK_SIZE: usize = 10_000;
    let b: Vec<_> = g1.chunks(CHUNK_SIZE).zip(g2.chunks(CHUNK_SIZE)).collect();
    let v: Vec<_> = b
        .into_par_iter()
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
        pairs
            .into_par_iter()
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
