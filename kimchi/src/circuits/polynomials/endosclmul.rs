//! This module implements short Weierstrass curve endomorphism optimised variable base
//! scalar multiplication custom Plonk polynomials.
//!
//! EVBSM gate constraints
//!
//! <pre>
//!     b1*(b1-1) = 0
//!     b2*(b2-1) = 0
//!     b3*(b3-1) = 0
//!     b4*(b4-1) = 0
//!     ((1 + (endo - 1) * b2) * xt - xp) * s1 = (2*b1-1)*yt - yp
//!     (2*xp – s1^2 + (1 + (endo - 1) * b2) * xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
//!     (yr + yp)^2 = (xp – xr)^2 * (s1^2 – (1 + (endo - 1) * b2) * xt + xr)
//!     ((1 + (endo - 1) * b2) * xt - xr) * s3 = (2*b3-1)*yt - yr
//!     (2*xr – s3^2 + (1 + (endo - 1) * b4) * xt) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
//!     (ys + yr)^2 = (xr – xs)^2 * (s3^2 – (1 + (endo - 1) * b4) * xt + xs)
//!     n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
//! </pre>
//!
//! The constraints above are derived from the following EC Affine arithmetic equations:
//!
//! <pre>
//!     (xq1 - xp) * s1 = yq1 - yp
//!     (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
//!     (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
//!
//!     (xq2 - xr) * s3 = yq2 - yr
//!     (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
//!     (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)
//! </pre>

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::boolean, prologue::*, Cache, ConstantExpr},
    gate::GateType,
    witness::COLUMNS,
};
use ark_ff::{FftField, Field, One};
use std::marker::PhantomData;

/// Implementation of the EndosclMul gate.
#[derive(Default)]
pub struct EndosclMul<F>(PhantomData<F>);

impl<F> Argument<F> for EndosclMul<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::EndoMul);
    const CONSTRAINTS: usize = 11;

    fn constraints() -> Vec<E<F>> {
        let b1 = witness_curr(11);
        let b2 = witness_curr(12);
        let b3 = witness_curr(13);
        let b4 = witness_curr(14);

        let xt = witness_curr(0);
        let yt = witness_curr(1);

        let xs = witness_next(4);
        let ys = witness_next(5);

        let xp = witness_curr(4);
        let yp = witness_curr(5);

        let xr = witness_curr(7);
        let yr = witness_curr(8);

        let mut cache = Cache::default();

        let s1 = witness_curr(9);
        let s3 = witness_curr(10);

        let endo_minus_1 = E::Constant(ConstantExpr::EndoCoefficient - ConstantExpr::one());
        let xq1 = cache.cache((E::one() + b1.clone() * endo_minus_1.clone()) * xt.clone());
        let xq2 = cache.cache((E::one() + b3.clone() * endo_minus_1) * xt);

        let yq1 = (b2.clone().double() - E::one()) * yt.clone();
        let yq2 = (b4.clone().double() - E::one()) * yt;

        let s1_squared = cache.cache(s1.clone().square());
        let s3_squared = cache.cache(s3.clone().square());

        // n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
        let n = witness_curr(6);
        let n_constraint =
            (((n.double() + b1.clone()).double() + b2.clone()).double() + b3.clone()).double()
                + b4.clone()
                - witness_next(6);

        let xp_xr = cache.cache(xp.clone() - xr.clone());
        let xr_xs = cache.cache(xr.clone() - xs.clone());

        let ys_yr = cache.cache(ys + yr.clone());
        let yr_yp = cache.cache(yr.clone() + yp.clone());

        vec![
            // verify booleanity of the scalar bits
            boolean(&b1),
            boolean(&b2),
            boolean(&b3),
            boolean(&b4),
            // (xq1 - xp) * s1 = yq1 - yp
            ((xq1.clone() - xp.clone()) * s1.clone()) - (yq1 - yp.clone()),
            // (2*xp – s1^2 + xq1) * ((xp - xr) * s1 + yr + yp) = (xp - xr) * 2*yp
            (((xp.double() - s1_squared.clone()) + xq1.clone())
                * ((xp_xr.clone() * s1) + yr_yp.clone()))
                - (yp.double() * xp_xr.clone()),
            // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
            yr_yp.square() - (xp_xr.square() * ((s1_squared - xq1) + xr.clone())),
            // (xq2 - xr) * s3 = yq2 - yr
            ((xq2.clone() - xr.clone()) * s3.clone()) - (yq2 - yr.clone()),
            // (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr - xs) * 2*yr
            (((xr.double() - s3_squared.clone()) + xq2.clone())
                * ((xr_xs.clone() * s3) + ys_yr.clone()))
                - (yr.double() * xr_xs.clone()),
            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)
            ys_yr.square() - (xr_xs.square() * ((s3_squared - xq2) + xs)),
            n_constraint,
        ]
    }
}

/// The result of performing an endoscaling: the accumulated curve point
/// and scalar.
pub struct EndoMulResult<F> {
    pub acc: (F, F),
    pub n: F,
}

/// Generates the witness_curr values for a series of endoscaling constraints.
pub fn gen_witness<F: Field + std::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    endo: F,
    base: (F, F),
    bits: &[bool],
    acc0: (F, F),
) -> EndoMulResult<F> {
    let bits_per_row = 4;
    let rows = bits.len() / 4;
    assert_eq!(0, bits.len() % 4);

    let bits: Vec<_> = bits.iter().map(|x| F::from(*x as u64)).collect();
    let one = F::one();

    let mut acc = acc0;
    let mut n_acc = F::zero();

    // TODO: Could be more efficient
    for i in 0..rows {
        let b1 = bits[i * bits_per_row];
        let b2 = bits[i * bits_per_row + 1];
        let b3 = bits[i * bits_per_row + 2];
        let b4 = bits[i * bits_per_row + 3];

        let (xt, yt) = base;
        let (xp, yp) = acc;

        let xq1 = (one + (endo - one) * b1) * xt;
        let yq1 = (b2.double() - one) * yt;

        let s1 = (yq1 - yp) / (xq1 - xp);
        let s1_squared = s1.square();
        // (2*xp – s1^2 + xq) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
        // => 2 yp / (2*xp – s1^2 + xq) = s1 + (yr + yp) / (xp – xr)
        // => 2 yp / (2*xp – s1^2 + xq) - s1 = (yr + yp) / (xp – xr)
        //
        // s2 := 2 yp / (2*xp – s1^2 + xq) - s1
        //
        // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
        // => (s1^2 – xq1 + xr) = (yr + yp)^2 / (xp – xr)^2
        //
        // => xr = s2^2 - s1^2 + xq
        // => yr = s2 * (xp - xr) - yp
        let s2 = yp.double() / (xp.double() + xq1 - s1_squared) - s1;

        // (xr, yr)
        let xr = xq1 + s2.square() - s1_squared;
        let yr = (xp - xr) * s2 - yp;

        let xq2 = (one + (endo - one) * b3) * xt;
        let yq2 = (b4.double() - one) * yt;
        let s3 = (yq2 - yr) / (xq2 - xr);
        let s3_squared = s3.square();
        let s4 = yr.double() / (xr.double() + xq2 - s3_squared) - s3;

        let xs = xq2 + s4.square() - s3_squared;
        let ys = (xr - xs) * s4 - yr;

        let row = i + row0;

        w[0][row] = base.0;
        w[1][row] = base.1;
        w[4][row] = xp;
        w[5][row] = yp;
        w[6][row] = n_acc;
        w[7][row] = xr;
        w[8][row] = yr;
        w[9][row] = s1;
        w[10][row] = s3;
        w[11][row] = b1;
        w[12][row] = b2;
        w[13][row] = b3;
        w[14][row] = b4;

        acc = (xs, ys);

        n_acc.double_in_place();
        n_acc += b1;
        n_acc.double_in_place();
        n_acc += b2;
        n_acc.double_in_place();
        n_acc += b3;
        n_acc.double_in_place();
        n_acc += b4;
    }
    w[4][row0 + rows] = acc.0;
    w[5][row0 + rows] = acc.1;
    w[6][row0 + rows] = n_acc;

    EndoMulResult { acc, n: n_acc }
}
