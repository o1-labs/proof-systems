/*****************************************************************************************************************
This source file implements constraint polynomials for non-special point doubling on Weierstrass curve

DOUBLE gate constraints
•	4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
•	2 * y1 * (y2 + y1) = (3 * x1^2) * (x1 – x2)
•	y1 * r1 = 1

The constraints above are derived from the following EC Affine arithmetic equations:

Doubling

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    y2 = y1 + s * (x2 – x1)

    =>

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    2 * y1 * (y2 - y1) = 3 * x1^2 * (x2 – x1)

    =>

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use rayon::prelude::*;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // EC Affine doubling constraint quotient poly contribution computation
    pub fn double_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        alpha: &[F],
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>) {
        if self.doublem.is_zero() {
            return (self.zero4.clone(), self.zero8.clone())
        }

        let (c1, x1_to_2) = {
            let this = &polys.d8.this.w;

            let x1 = &this[0];
            let y1 = &this[1];
            let x2 = &this[2];

            let x1_to_2 = x1.square();

            let x1_to_4_times_9 = {
                let x1_to_4 = x1_to_2.square();
                let mut res = &x1_to_4 + &x1_to_4;
                res.evals.par_iter_mut().for_each(|x| { x.double_in_place(); });
                res.evals.par_iter_mut().for_each(|x| { x.double_in_place(); });
                res += &x1_to_4;
                drop(x1_to_4);
                res
            };
            // res = 2 x1
            let mut res = x1 + x1;
            // res = x2 + 2 x1
            res += &x2;
            res.evals.par_iter_mut().enumerate().for_each(|(i, x)| {
                // res = y1^2 * (x2 + 2 x1)
                *x *= y1[i].square();
                // res = 2 * y1^2 * (x2 + 2 x1)
                x.double_in_place();
                // res = 4 * y1^2 * (x2 + 2 x1)
                x.double_in_place();
            });
            // res = 4 * y1^2 * (x2 + 2 * x1) - 9 * x1^4
            res -= &x1_to_4_times_9;
            (res, x1_to_2)
        };

        let (c2, c3) = {
            let this = &polys.d4.this.w;

            let x1 = &this[0];
            let y1 = &this[1];
            let x2 = &this[2];
            let y2 = &this[3];
            let r1 = &this[4];

            let rhs = {
                // rhs = (x1 - x2)
                let mut res = x1 - x2;
                let scale = x1_to_2.evals.len() / res.evals.len();
                assert!(scale > 0);
                // rhs = x1^2 * (x1 - x2)
                res.evals.par_iter_mut().enumerate().for_each(|(i, x)| *x *= x1_to_2[scale * i]);
                // rhs = 3 * x1^2 * (x1 - x2)
                res.evals.par_iter_mut().for_each(|x| *x += x.double());
                res
            };

            // res = y2 + y1
            let mut res = y2 + y1;
            // res = y1 * (y2 + y1)
            res *= y1;
            // res = 2 * y1 * (y2 + y1)
            res.evals.par_iter_mut().for_each(|x| { x.double_in_place(); });
            // res = 2 * y1 * (y2 + y1) - 3 * x1^2 * (x1 – x2)
            res -= &rhs;
            (res, &(y1 * r1) - &self.l04)
        };

        // TODO: Maybe the computation of (x3, y3, r1) should actually occur in this function

        let p8 = [
            // 4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
            c1,
        ];

        let p4 = [
            // 2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)
            c2,
            // y1 * r1 = 1
            c3,
        ];

            (
            &p4.iter()
                .skip(1)
                .zip(alpha.iter().skip(1))
                .map(|(p, a)| p.scale(*a))
                .fold(p4[0].scale(alpha[0]), |x, y| &x + &y)
                * &self.doubl4,
             &p8.iter()
                 .skip(1)
                 .zip(alpha[p4.len() + 1..].iter())
                 .map(|(p, a)| p.scale(*a))
                 .fold(p8[0].scale(alpha[p4.len()]), |x, y| &x + &y)
                 * &self.doubl8)
    }

    pub fn double_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        let this = &evals[0].w;

        let x1 = this[0];
        let y1 = this[1];
        let x2 = this[2];
        let y2 = this[3];
        let r1 = this[4];

        let x1_to_2 = x1.square();

        let c1 = {
            let x1_to_4_times_9 = {
                let x1_to_4 = x1_to_2.square();
                let mut res = x1_to_4 + x1_to_4;
                res.double_in_place();
                res.double_in_place();
                res += &x1_to_4;
                res
            };
            // res = 2 x1
            let mut res = x1 + x1;
            // res = x2 + 2 x1
            res += &x2;
            // res = y1^2 * (x2 + 2 x1)
            res *= y1.square();
            // res = 2 * y1^2 * (x2 + 2 x1)
            res.double_in_place();
            // res = 4 * y1^2 * (x2 + 2 x1)
            res.double_in_place();
            // res = 4 * y1^2 * (x2 + 2 * x1) - 9 * x1^4
            res -= &x1_to_4_times_9;
            res
        };

        let c2 = {
            let rhs = {
                // rhs = (x1 - x2)
                let mut res = x1 - x2;
                // rhs = x1^2 * (x1 - x2)
                res *= &x1_to_2;
                // rhs = 3 * x1^2 * (x1 - x2)
                res += res.double();
                res
            };

            // res = y2 + y1
            let mut res = y2 + y1;
            // res = y1 * (y2 + y1)
            res *= y1;
            // res = 2 * y1 * (y2 + y1)
            res.double_in_place();
            // res = 2 * y1 * (y2 + y1) - 3 * x1^2 * (x1 – x2)
            res -= &rhs;
            res
        };

        [ c2, y1 * r1 - F::one(), c1 ]
        .iter()
        .zip(alpha.iter())
        .map(|(p, a)| *p * a)
        .fold(F::zero(), |x, y| x + &y)
    }

    // EC Affine doubling constraint linearization poly contribution computation
    pub fn double_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        self.doublem.scale(Self::double_scalars(evals, alpha))
    }
}
