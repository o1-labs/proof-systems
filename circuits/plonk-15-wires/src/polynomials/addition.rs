/*****************************************************************************************************************

This source file implements non-special point Weierstrass curve additionconstraint polynomials.

    ADD gate constrains

        (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
        (x2 - x1) * r = 1

    The constrains above are derived from the following EC Affine arithmetic equations:

        (x2 - x1) * s = y2 - y1
        s * s = x1 + x2 + x3
        (x1 - x3) * s = y3 + y1

        =>

        (x2 - x1) * (y3 + y1) = (y1 - y2) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) = (y3 + y1) * (y3 + y1)

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::{EvalUtils, PolyUtils};

impl<Field: FftField + SquareRootField> ConstraintSystem<Field> {
    // EC Affine addition constraint quotient poly contribution computation
    pub fn ecad_quot(
        &self,
        polys: &WitnessOverDomains<Field>,
        alpha: &[Field],
    ) -> Evaluations<Field, D<Field>> {
        if self.addm.is_zero() {
            return self.zero4.clone();
        }
        /*
            (x2 - x1) * (y3 + y1) - (y2 - y1) * (x1 - x3)
            (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
            (x2 - x1) * r = 1
        */
        let w = &polys.d4.this.w;
        let y31 = &(&w[5] + &w[1]);
        let x13 = &(&w[0] - &w[4]);
        let x21 = &(&w[2] - &w[0]);

        let p = [
            &(x21 * y31) - &(&(&w[3] - &w[1]) * x13),
            &(&(&(&w[0] + &w[2]) + &w[4]) * &x13.pow(2)) - &y31.pow(2),
            (&(x21 * &w[6]) - &self.l04),
        ];

        &p.iter()
            .skip(1)
            .zip(alpha.iter().skip(1))
            .map(|(p, a)| p.scale(*a))
            .fold(p[0].scale(alpha[0]), |x, y| &x + &y)
            * &self.addl
    }

    pub fn ecad_scalars(evals: &Vec<ProofEvaluations<Field>>, alpha: &[Field]) -> Field {
        let w = evals[0].w;
        let y31 = w[5] + &w[1];
        let x13 = w[0] - &w[4];
        let x21 = w[2] - &w[0];

        [
            (x21 * y31) - &((w[3] - &w[1]) * x13),
            (w[0] + &w[2] + &w[4]) * &x13.square() - &y31.square(),
            x21 * &w[6] - &Field::one(),
        ]
        .iter()
        .zip(alpha.iter())
        .map(|(p, a)| *p * a)
        .fold(Field::zero(), |x, y| x + &y)
    }

    // EC Affine addition constraint linearization poly contribution computation
    pub fn ecad_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<Field>>,
        alpha: &[Field],
    ) -> DensePolynomial<Field> {
        self.addm.scale(Self::ecad_scalars(evals, alpha))
    }
}
