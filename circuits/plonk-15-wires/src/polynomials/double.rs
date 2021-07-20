/*****************************************************************************************************************
This source file implements constraint polynomials for non-special point doubling and tripling on Weierstrass curve

DOUBLE gate constraints
•	4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
•	2 * y1 * (y2 + y1) = (3 * x1^2) * (x1 – x2)
•	y1 * r1 = 1
•
•	(x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
•	(x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
•	(x2 - x1) * r2 = 1

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

Addition


    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

    =>

    (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
    (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::{EvalUtils, PolyUtils};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // EC Affine doubling constraint quotient poly contribution computation
    pub fn double_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        alpha: &[F],
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>) {
        if self.doublem.is_zero() {
            return (self.zero4.clone(), self.zero8.clone());
        }

        let p4 = &polys.d4.this.w;
        let p8 = &polys.d8.this.w;

        let p8 = [
            &(&p8[1].pow(2).scale(F::from(4 as u64)) * &(&p8[2] + &p8[0].scale(F::from(2 as u64))))
                - &p8[0].pow(4).scale(F::from(9 as u64)),
            &(&p8[1].scale(F::from(2 as u64)) * &(&p8[3] + &p8[1]))
                - &(&(&p8[0] - &p8[2]) * &p8[0].pow(2).scale(F::from(3 as u64))),
            &(&p8[1] * &p8[6]) - &self.l08,
        ];

        let y31 = &(&p4[5] + &p4[1]);
        let x13 = &(&p4[0] - &p4[4]);
        let x21 = &(&p4[2] - &p4[0]);

        let p4 = [
            &(x21 * y31) - &(&(&p4[3] - &p4[1]) * x13),
            &(&(&(&p4[0] + &p4[2]) + &p4[4]) * &x13.pow(2)) - &y31.pow(2),
            (&(x21 * &p4[7]) - &self.l04),
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
                * &self.doubl8,
        )
    }

    pub fn double_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        let w = &evals[0].w;
        let d = [
            (w[1].square() * &F::from(4 as u64) * &(w[2] + &w[0].double()))
                - &(w[0].square().square() * &F::from(9 as u64)),
            (w[1].double() * &(w[3] + &w[1]))
                - &((w[0] - &w[2]) * &w[0].square() * &F::from(3 as u64)),
            w[1] * &w[6] - &F::one(),
        ];

        let y31 = w[5] + &w[1];
        let x13 = w[0] - &w[4];
        let x21 = w[2] - &w[0];

        let a = [
            (x21 * y31) - &((w[3] - &w[1]) * x13),
            (w[0] + &w[2] + &w[4]) * &x13.square() - &y31.square(),
            x21 * &w[7] - &F::one(),
        ];

        a.iter()
            .zip(alpha.iter())
            .map(|(p, a)| *p * a)
            .fold(F::zero(), |x, y| x + &y)
            + &d.iter()
                .zip(alpha[a.len()..].iter())
                .map(|(p, a)| *p * a)
                .fold(F::zero(), |x, y| x + &y)
    }

    // EC Affine doubling constraint linearization poly contribution computation
    pub fn double_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        self.doublem.scale(Self::double_scalars(evals, alpha))
    }
}
