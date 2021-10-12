/*****************************************************************************************************************

This source file implements short Weierstrass curve endomorphism optimised variable base
scalar multiplication custom Plonk polynomials.

EVBSM gate constraints
    b1*(b1-1) = 0
    b2*(b2-1) = 0
    b3*(b3-1) = 0
    b4*(b4-1) = 0
    ((1 + (endo - 1) * b2) * xt - xp) * s1 = (2*b1-1)*yt - yp
    (2*xp – s1^2 + (1 + (endo - 1) * b2) * xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
    (yr + yp)^2 = (xp – xr)^2 * (s1^2 – (1 + (endo - 1) * b2) * xt + xr)
    ((1 + (endo - 1) * b2) * xt - xr) * s3 = (2*b3-1)*yt - yr
    (2*xr – s3^2 + (1 + (endo - 1) * b4) * xt) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
    (ys + yr)^2 = (xr – xs)^2 * (s3^2 – (1 + (endo - 1) * b4) * xt + xs)
    n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4

The constraints above are derived from the following EC Affine arithmetic equations:

    (xq1 - xp) * s1 = yq1 - yp
    (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
    (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)

    (xq2 - xr) * s3 = yq2 - yr
    (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
    (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use crate::wires::COLUMNS;
use rayon::prelude::*;

pub struct EndoMulResult<F> {
    pub acc: (F, F),
    pub n: F,
}

pub fn witness<F: FftField + std::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    endo: F,
    base: (F, F),
    bits: &Vec<bool>,
    acc0: (F, F)) -> EndoMulResult<F> {

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
        let yq1 = (b2.double() - one)*yt;

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
        let s2 = yp.double() / ( xp.double() + xq1 - s1_squared) - s1;

        // (xr, yr)
        let xr = xq1 + s2.square() - s1_squared;
        let yr = (xp - xr) * s2 - yp;

        let xq2 = (one + (endo - one) * b3) * xt;
        let yq2 = (b4.double() - one)*yt;
        let s3 = (yq2 - yr) / (xq2 - xr);
        let s3_squared = s3.square();
        let s4 = yr.double() / ( xr.double() + xq2 - s3_squared) - s3;

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

    EndoMulResult {
        acc,
        n: n_acc
    }
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // endomorphism optimised scalar multiplication constraint quotient poly contribution computation
    pub fn endomul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>> {
        if self.emulm.is_zero() {
            return self.zero8.clone();
        }

        let this = &polys.d8.this.w;
        let next = &polys.d8.next.w;

        let b1 = &this[11];
        let b2 = &this[12];
        let b3 = &this[13];
        let b4 = &this[14];

        let xt = &this[0];
        let yt = &this[1];

        let xs = &next[4];
        let ys = &next[5];

        let xp = &this[4];
        let yp = &this[5];

        let xr = &this[7];
        let yr = &this[8];

        let s1 = &this[9];
        let s3 = &this[10];

        let xq1 = &(&(&self.l08 + &b1.scale(self.endo - F::one())) * &xt);
        let xq2 = &(&(&self.l08 + &b3.scale(self.endo - F::one())) * &xt);

        let yq1 = &(&(&(b2 + b2) - &self.l08)*yt);
        let yq2 = &(&(&(b4 + b4) - &self.l08)*yt);

        let s1_squared = &s1.square();
        let s3_squared = &s3.square();

        // n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
        let n_constraint = {
            let n = &this[6];
            let mut res = n + n;
            res += b1;
            res.evals.par_iter_mut().for_each(|x| { x.double_in_place(); });
            res += b2;
            res.evals.par_iter_mut().for_each(|x| { x.double_in_place(); });
            res += b3;
            res.evals.par_iter_mut().for_each(|x| { x.double_in_place(); });
            res += b4;
            res -= &next[6];
            res
        };

        let p = [
            // verify booleanity of the scalar bits
            b1 - &b1.square(),
            b2 - &b2.square(),
            b3 - &b3.square(),
            b4 - &b4.square(),
            // (xq1 - xp) * s1 = yq1 - yp
            &(&(xq1 - xp) * s1) - &(yq1 - yp),
            // (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
            &(&(&(&(xp + xp) - s1_squared) + xq1) * &(&(&(xp - xr) * s1) + &(yr + yp)))
                -
                &(&(yp + yp) * &(xp - xr)),
            // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
            &(yr + yp).square() - &(&(xp - xr).square() * &(&(s1_squared - xq1) + xr)),
            // (xq2 - xr) * s3 = yq2 - yr
            &(&(xq2 - xr) * s3) - &(yq2 - yr),
            // (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
            &(&(&(&(xr + xr) - s3_squared) + xq2) * &(&(&(xr - xs) * s3) + &(ys + yr)))
                -
                &(&(yr + yr) * &(xr - xs)),

            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)
            &(ys + yr).square() - &(&(xr - xs).square() * &(&(s3_squared - xq2) + xs)),
            n_constraint,
        ];
        &p.iter()
            .skip(1)
            .zip(alpha.iter().skip(1))
            .map(|(p, a)| p.scale(*a))
            .fold(p[0].scale(alpha[0]), |x, y| &x + &y)
            * &self.emull
    }

    pub fn endomul_scalars(evals: &Vec<ProofEvaluations<F>>, endo: F, alpha: &[F]) -> F {
        let this = &evals[0].w;
        let next = &evals[1].w;

        let b1 = this[11];
        let b2 = this[12];
        let b3 = this[13];
        let b4 = this[14];

        let xt = this[0];
        let yt = this[1];

        let xs = next[4];
        let ys = next[5];

        let xp = this[4];
        let yp = this[5];

        let xr = this[7];
        let yr = this[8];

        let s1 = this[9];
        let s3 = this[10];

        let xq1 = (F::one() + (b1 * (endo - F::one()))) * xt;
        let xq2 = (F::one() + (b3 * (endo - F::one()))) * xt;

        let yq1 = ((b2 + b2) - F::one())*yt;
        let yq2 = ((b4 + b4) - F::one())*yt;

        let s1_squared = s1.square();
        let s3_squared = s3.square();

        let n_constraint = {
            let mut res = this[6].double();
            res += b1;
            res.double_in_place();
            res += b2;
            res.double_in_place();
            res += b3;
            res.double_in_place();
            res += b4;
            res -= next[6];
            res
        };

        [
            // verify booleanity of the scalar bits
            b1 - b1.square(),
            b2 - b2.square(),
            b3 - b3.square(),
            b4 - b4.square(),
            ((xq1 - xp) * s1) - (yq1 - yp),
            // (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
            ((((xp + xp) - s1_squared) + xq1) * (((xp - xr) * s1) + (yr + yp)))
                -
                ((yp + yp) * (xp - xr)),
            // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
            (yr + yp).square() - ((xp - xr).square() * ((s1_squared - xq1) + xr)),
            // (xq2 - xr) * s3 = yq2 - yr
            ((xq2 - xr) * s3) - (yq2 - yr),
            // (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
            ((((xr + xr) - s3_squared) + xq2) * (((xr - xs) * s3) + (ys + yr)))
                -
                ((yr + yr) * (xr - xs)),
            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)
            (ys + yr).square() - ((xr - xs).square() * ((s3_squared - xq2) + xs)),
            n_constraint,
        ]
        .iter()
        .zip(alpha.iter())
        .map(|(p, a)| *p * a)
        .fold(F::zero(), |x, y| x + &y)
    }

    // endomorphism optimised scalar multiplication constraint linearization poly contribution computation
    pub fn endomul_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        self.emulm
            .scale(Self::endomul_scalars(evals, self.endo, alpha))
    }
}
