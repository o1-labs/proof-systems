/*****************************************************************************************************************

This source file implements non-special point Weierstrass curve additionconstraint polynomials.

    ADD gate constrains

        (x1 - x3) * (y2 - y1) = (y3 + y1) * (x2 - x1)
        (y2 - y1)^2 = (x1 + x2 + x3) * (x2 - x1)^2
        (x2 - x1) * r = 1

    The constrains above are derived from the following EC Affine arithmetic equations:

        (x2 - x1) * s = y2 - y1
        s * s = x1 + x2 + x3
        (x1 - x3) * s = y3 + y1

        =>
        s := (y2 - y1) / (x2 - x1)
        s * s = x1 + x2 + x3
        (x1 - x3) * s = y3 + y1

        =>
        x2 != x1
        (y2 - y1)^2 = (x1 + x2 + x3) * (x2 - x1)^2
        (x1 - x3) * (y2 - y1) = (y3 + y1) * (x2 - x1)

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::{ExtendedEvaluations, ExtendedDensePolynomial};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // EC Affine addition constraint quotient poly contribution computation
    pub fn ecad_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>> {
        if self.addm.is_zero() {
            return self.zero4.clone();
        }
        /*
            (x1 - x3) * (y2 - y1) = (y3 + y1) * (x2 - x1)
            (y2 - y1)^2 = (x1 + x2 + x3) * (x2 - x1)^2
            (x2 - x1) * r = 1
        */
        let w = &polys.d4.this.w;
        let x1 = &w[0];
        let y1 = &w[1];
        let x2 = &w[2];
        let y2 = &w[3];
        let x3 = &w[4];
        let y3 = &w[5];
        let r = &w[6];

        let y21 = &(y2 - y1);
        let x21 = &(x2 - x1);

        let c1 = &(&(x1 - x3) * &y21) - &(&(y3 + y1) * x21);
        let c2 = &y21.square() - &(&(&(x1 + x2) + x3) * &x21.square());

        let p = [
            c1,
            c2,
            (&(x21 * r) - &self.l04),
        ];

        &p.iter()
            .skip(1)
            .zip(alpha.iter().skip(1))
            .map(|(p, a)| p.scale(*a))
            .fold(p[0].scale(alpha[0]), |x, y| &x + &y)
            * &self.addl
    }

    pub fn ecad_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F {
        let w = evals[0].w;
        let x1 = w[0];
        let y1 = w[1];
        let x2 = w[2];
        let y2 = w[3];
        let x3 = w[4];
        let y3 = w[5];
        let r = w[6];

        let y21 = y2 - y1;
        let x21 = x2 - x1;

        let c1 = ((x1 - x3) * y21) - ((y3 + y1) * x21);
        let c2 = y21.square() - (((x1 + x2) + x3) * x21.square());

        [
            c1,
            c2,
            ((x21 * r) - F::one()),
        ]
        .iter()
        .zip(alpha.iter())
        .map(|(p, a)| *p * a)
        .fold(F::zero(), |x, y| x + &y)
    }

    // EC Affine addition constraint linearization poly contribution computation
    pub fn ecad_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F> {
        self.addm.scale(Self::ecad_scalars(evals, alpha))
    }
}
