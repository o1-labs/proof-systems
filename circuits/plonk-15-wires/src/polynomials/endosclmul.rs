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
use oracle::utils::{EvalUtils, PolyUtils};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // endomorphism optimised scalar multiplication constraint quotient poly contribution computation
    pub fn endomul_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>> {
        if self.emulm.is_zero() {
            return self.zero8.clone();
        }

        let this = &polys.d8.this.w;
        let next = &polys.d8.next.w;

        let xq1 = &(&(&self.l08 + &next[0].scale(self.endo - F::one())) * &this[12]);
        let xq2 = &(&(&self.l08 + &next[0].scale(self.endo - F::one())) * &this[14]);

        let p = [
            // verify booleanity of the scalar bits
            &this[11] - &this[11].pow(2),
            &this[12] - &this[12].pow(2),
            &this[13] - &this[13].pow(2),
            &this[14] - &this[14].pow(2),
            // ((1 + (endo - 1) * b2) * xt - xp) * s1 = (2*b1-1)*yt - yp
            &(&(xq1 - &this[4]) * &this[9])
                - &(&(&(&this[11].scale(F::from(2 as u64)) - &self.l08) * &this[2]) + &this[5]),
            // (2*xp – s1^2 + (1 + (endo - 1) * b2) * xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
            &(&(&(&(&this[4].scale(F::from(2 as u64)) - &this[9].pow(2)) + xq1)
                * &(&(&this[4] - &this[7]) * &this[9]))
                + &(&this[8] + &this[5]))
                - &(&(&this[4] - &this[7]) * &this[5].scale(F::from(2 as u64))),
            // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – (1 + (endo - 1) * b2) * xt + xr)
            &(&this[8] + &this[5]).pow(2)
                - &(&(&this[4] - &this[7]).pow(2) * &(&this[9].pow(2) - &(xq1 + &this[7]))),
            // ((1 + (endo - 1) * b2) * xt - xr) * s3 = (2*b3-1)*yt - yr
            &(&(xq2 - &this[7]) * &this[10])
                - &(&(&(&this[13].scale(F::from(2 as u64)) - &self.l08) * &this[2]) + &this[8]),
            // (2*xr – s3^2 + (1 + (endo - 1) * b4) * xt) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
            &(&(&(&(&this[7].scale(F::from(2 as u64)) - &this[10].pow(2)) + xq2)
                * &(&(&this[7] - &this[2]) * &this[10]))
                + &(&this[3] + &this[8]))
                - &(&(&this[7] - &this[2]) * &this[8].scale(F::from(2 as u64))),
            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – (1 + (endo - 1) * b4) * xt + xs)
            &(&this[3] + &this[8]).pow(2)
                - &(&(&this[7] - &this[2]).pow(2) * &(&this[10].pow(2) - &(xq2 + &this[2]))),
            // n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
            &(&(&(&(&next[6].scale(F::from(2 as u64)) + &this[11]).scale(F::from(2 as u64))
                + &this[12])
                .scale(F::from(2 as u64))
                + &this[13])
                .scale(F::from(2 as u64))
                + &this[14])
                - &this[6],
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
        let xq1 = (F::one() + &(this[12] * &(endo - &F::one()))) * &this[0];
        let xq2 = (F::one() + &(this[14] * &(endo - &F::one()))) * &this[0];

        [
            // verify booleanity of the scalar bits
            this[11] - &this[11].square(),
            this[12] - &this[12].square(),
            this[13] - &this[13].square(),
            this[14] - &this[14].square(),
            // ((1 + (endo - 1) * b2) * xt - xp) * s1 = (2*b1-1)*yt - yp
            ((xq1 - &this[4]) * &this[9])
                - &(((this[11].double() - &F::one()) * &this[2]) + &this[5]),
            // (2*xp – s1^2 + (1 + (endo - 1) * b2) * xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
            ((((this[4].double() - &this[9].square()) + xq1) * &((this[4] - &this[7]) * &this[9]))
                + &(this[8] + &this[5]))
                - ((this[4] - &this[7]) * &this[5].double()),
            // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – (1 + (endo - 1) * b2) * xt + xr)
            (this[8] + &this[5]).square()
                - ((this[4] - &this[7]).square() * &(this[9].square() - &(xq1 + &this[7]))),
            // ((1 + (endo - 1) * b2) * xt - xr) * s3 = (2*b3-1)*yt - yr
            ((xq2 - &this[7]) * &this[10])
                - &(((this[13].double() - &F::one()) * &this[2]) + &this[8]),
            // (2*xr – s3^2 + (1 + (endo - 1) * b4) * xt) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
            ((((this[7].double() - &this[10].square()) + xq2)
                * &((this[7] - &this[2]) * &this[10]))
                + &(this[3] + &this[8]))
                - ((this[7] - &this[2]) * &this[8].double()),
            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – (1 + (endo - 1) * b4) * xt + xs)
            (this[3] + &this[8]).square()
                - &((this[7] - &this[2]).square() * &(this[10].square() - &(xq2 + &this[2]))),
            // n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
            ((((evals[1].w[6].double() + &this[11]).double() + &this[12]).double() + &this[13])
                .double()
                + &this[14])
                - &this[6],
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
