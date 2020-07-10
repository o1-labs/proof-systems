/*****************************************************************************************************************

This source file implements permutation constraint polynomial.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use crate::scalars::{ProofEvaluations, RandomOracles};
use crate::polynomials::WitnessOverDomains;
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
        let l0 = &self.l0.scale(oracles.gamma);

        (&(&(&(&(&lagrange.d4.this.l + &(l0 + &self.l1.scale(oracles.beta))) *
        &(&lagrange.d4.this.r + &(l0 + &self.l1.scale(oracles.beta * &self.r)))) *
        &(&lagrange.d4.this.o + &(l0 + &self.l1.scale(oracles.beta * &self.o)))) *
        &lagrange.d4.this.z)
        -
        &(&(&(&(&lagrange.d4.this.l + &(l0 + &self.sigmal4[0].scale(oracles.beta))) *
        &(&lagrange.d4.this.r + &(l0 + &self.sigmal4[1].scale(oracles.beta)))) *
        &(&lagrange.d4.this.o + &(l0 + &self.sigmal4[2].scale(oracles.beta)))) *
        &lagrange.d4.next.z)).scale(oracles.alpha)
    }

    // permutation linearization poly contribution computation
    pub fn perm_lnrz(&self, e: &Vec<ProofEvaluations<F>>, oracles: &RandomOracles<F>) -> DensePolynomial<F>
    {
        self.sigmam[2].scale
        (
            (e[0].l + &(oracles.beta * &e[0].sigma1) + &oracles.gamma) *
            &(e[0].r + &(oracles.beta * &e[0].sigma2) + &oracles.gamma) *
            &(oracles.beta * &e[1].z * &oracles.alpha)
        )
    }
}
