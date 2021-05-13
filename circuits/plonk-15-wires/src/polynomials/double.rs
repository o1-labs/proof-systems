/*****************************************************************************************************************

This source file implements constraint polynomials for non-special point doubling on Weierstrass curve

DOUBLE gate constrains

	4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
	2 * y1 * (y2 + y1) = (3 * x1^2) * (x1 – x2)
	y1 * r1 = 1
	4 * y2^2 * (x4 + 2*x2) = 9 * x2^4
	2 * y2 * (y4 + y2) = (3 * x2^2) * (x2 – x4)
	y2 * r2 = 1
	4 * y4^2 * (x8 + 2*x4) = 9 * x4^4
	2 * y4 * (y8 + y4) = (3 * x4^2) * (x4 – x8)
	y4 * r3 = 1
	4 * y8^2 * (x16 + 2*x8) = 9 * x8^4
	2 * y8 * (y16 + y8) = (3 * x8^2) * (x8 – x16)
	y8 * r4 = 1

The constrains above are derived from the following EC Affine arithmetic equations:

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    y2 = y1 + s * (x2 – x1)

    =>

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    2 * y1 * (y2 - y1) = 3 * x1^2 * (x2 – x1)

    =>

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 - y1) = 3 * x1^2 * (x2 – x1)

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // EC Affine doubling constraint quotient poly contribution computation
    pub fn double_quot(&self, polys: &WitnessOverDomains<F>, alpha: &[F]) -> Evaluations<F, D<F>>
    {
        if self.doublem.is_zero() {return self.zero8.clone()}

        let p = &polys.d8.this;
        let p =
        [
            &(&p.w[1].pow(2).scale(F::from(4 as u64)) * &(&p.w[2] +
                &p.w[0].scale(F::from(2 as u64)))) - &p.w[0].pow(4).scale(F::from(9 as u64)),
            &(&p.w[1].scale(F::from(2 as u64)) * &(&p.w[3] + &p.w[1])) -
                &(&(&p.w[0] - &p.w[2]) * &p.w[0].pow(2).scale(F::from(3 as u64))),
            &(&p.w[1] * &p.w[10]) - &self.l08,

            &(&p.w[3].pow(2).scale(F::from(4 as u64)) * &(&p.w[6] +
                &p.w[2].scale(F::from(2 as u64)))) - &p.w[2].pow(4).scale(F::from(9 as u64)),
            &(&p.w[3].scale(F::from(2 as u64)) * &(&p.w[7] + &p.w[3])) -
                &(&(&p.w[2] - &p.w[6]) * &p.w[2].pow(2).scale(F::from(3 as u64))),
            &(&p.w[3] * &p.w[11]) - &self.l08,

            &(&p.w[7].pow(2).scale(F::from(4 as u64)) * &(&p.w[8] +
                &p.w[6].scale(F::from(2 as u64)))) - &p.w[6].pow(4).scale(F::from(9 as u64)),
            &(&p.w[7].scale(F::from(2 as u64)) * &(&p.w[9] + &p.w[7])) -
                &(&(&p.w[6] - &p.w[8]) * &p.w[6].pow(2).scale(F::from(3 as u64))),
            &(&p.w[7] * &p.w[12]) - &self.l08,

            &(&p.w[9].pow(2).scale(F::from(4 as u64)) * &(&p.w[4] +
                &p.w[8].scale(F::from(2 as u64)))) - &p.w[8].pow(4).scale(F::from(9 as u64)),
            &(&p.w[9].scale(F::from(2 as u64)) * &(&p.w[5] + &p.w[9])) -
                &(&(&p.w[8] - &p.w[4]) * &p.w[8].pow(2).scale(F::from(3 as u64))),
            &(&p.w[9] * &p.w[13]) - &self.l08,
        ];

        &p.iter().skip(1).zip(alpha.iter().skip(1)).map(|(p, a)| p.scale(*a)).
            fold(p[0].scale(alpha[0]), |x, y| &x + &y) * &self.doublel
    }

    pub fn double_scalars(evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> F
    {
        let s = &evals[0];
        let s =
        [
            (s.w[1].square() * &F::from(4 as u64) * &(s.w[2] +
                &s.w[0].double())) - &(s.w[0].square().square() * &F::from(9 as u64)),
            (s.w[1].double() * &(s.w[3] + &s.w[1])) -
                &((s.w[0] - &s.w[2]) * &s.w[0].square() * &F::from(3 as u64)),
            s.w[1] * &s.w[10] - &F::one(),
            
            (s.w[3].square() * &F::from(4 as u64) * &(s.w[6] +
                &s.w[2].double())) - &(s.w[2].square().square() * &F::from(9 as u64)),
            (s.w[3].double() * &(s.w[7] + &s.w[3])) -
                &((s.w[2] - &s.w[6]) * &s.w[2].square() * &F::from(3 as u64)),
            s.w[3] * &s.w[11] - &F::one(),
            
            (s.w[7].square() * &F::from(4 as u64) * &(s.w[8] +
                &s.w[6].double())) - &(s.w[0].square().square() * &F::from(9 as u64)),
            (s.w[7].double() * &(s.w[9] + &s.w[7])) -
                &((s.w[6] - &s.w[8]) * &s.w[6].square() * &F::from(3 as u64)),
            s.w[7] * &s.w[13] - &F::one(),
            
            (s.w[9].square() * &F::from(4 as u64) * &(s.w[4] +
                &s.w[8].double())) - &(s.w[8].square().square() * &F::from(9 as u64)),
            (s.w[9].double() * &(s.w[5] + &s.w[9])) -
                &((s.w[8] - &s.w[4]) * &s.w[8].square() * &F::from(3 as u64)),
            s.w[9] * &s.w[14] - &F::one(),            
        ];

        s.iter().zip(alpha.iter()).map(|(p, a)| *p * a).fold(F::one(), |x, y| x + &y)
    }

    // EC Affine doubling constraint linearization poly contribution computation
    pub fn double_lnrz(&self, evals: &Vec<ProofEvaluations<F>>, alpha: &[F]) -> DensePolynomial<F>
    {
        self.doublem.scale(Self::double_scalars(evals, alpha))
    }
}
