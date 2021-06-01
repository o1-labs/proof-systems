/*****************************************************************************************************************

This source file implements permutation constraint polynomial.

*****************************************************************************************************************/

use ark_ff::{FftField, SquareRootField};
use ark_poly::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use crate::scalars::{ProofEvaluations, RandomOracles};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // permutation quotient poly contribution computation
    pub fn perm_quot
    (
        &self,
        lagrange: &WitnessOverDomains<F>,
        oracles: &RandomOracles<F>,
    ) -> Evaluations<F, D<F>>
    {
        let l0 = &self.l08.scale(oracles.gamma);

        &((&(&(&(&(&lagrange.d8.this.l + &(l0 + &self.l1.scale(oracles.beta))) *
        &(&lagrange.d8.this.r + &(l0 + &self.l1.scale(oracles.beta * &self.r)))) *
        &(&lagrange.d8.this.o + &(l0 + &self.l1.scale(oracles.beta * &self.o)))) *
        &lagrange.d8.this.z)
        -
        &(&(&(&(&lagrange.d8.this.l + &(l0 + &self.sigmal4[0].scale(oracles.beta))) *
        &(&lagrange.d8.this.r + &(l0 + &self.sigmal4[1].scale(oracles.beta)))) *
        &(&lagrange.d8.this.o + &(l0 + &self.sigmal4[2].scale(oracles.beta)))) *
        &lagrange.d8.next.z)).scale(oracles.alpha))
        *
        &self.zkpl
    }

    pub fn perm_lnrz
    (
        &self, e: &Vec<ProofEvaluations<F>>,
        z: &DensePolynomial<F>,
        oracles: &RandomOracles<F>,
        alpha: &[F]
    ) -> DensePolynomial<F>
    {
        let scalars = Self::perm_scalars
        (
            e,
            oracles,
            (self.r, self.o),
            alpha,
            self.domain.d1.size,
            self.zkpm.evaluate(oracles.zeta),
            self.sid[self.domain.d1.size as usize -3]
        );
        &z.scale(scalars[0]) + &self.sigmam[2].scale(scalars[1])
    }

    // permutation linearization poly contribution computation
    pub fn perm_scalars
    (
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        shift: (F, F),
        alpha: &[F],
        n: u64,
        z: F,
        w: F,
    ) -> Vec<F>
    {
        let bz = oracles.beta * &oracles.zeta;
        let mut denominator = [oracles.zeta - &F::one(), oracles.zeta - &w];
        algebra::fields::batch_inversion::<F>(&mut denominator);
        let numerator = oracles.zeta.pow(&[n]) - &F::one();

        vec!
        [
            (e[0].l + &bz + &oracles.gamma) *
            &(e[0].r + &(bz * &shift.0) + &oracles.gamma) *
            &(e[0].o + &(bz * &shift.1) + &oracles.gamma) *
            &oracles.alpha * &z +
            &(alpha[0] * &numerator * &denominator[0]) +
            &(alpha[1] * &numerator * &denominator[1])
            ,
            -(e[0].l + &(oracles.beta * &e[0].sigma1) + &oracles.gamma) *
            &(e[0].r + &(oracles.beta * &e[0].sigma2) + &oracles.gamma) *
            &(e[1].z * &oracles.beta * &oracles.alpha * &z)
        ]
    }
}
