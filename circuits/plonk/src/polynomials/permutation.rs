/*****************************************************************************************************************

This source file implements permutation constraint polynomial.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
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
        let l0 = &self.l0.scale(oracles.gamma);

        (&(&(&(&(&lagrange.d8.this.l + &(l0 + &self.l1.scale(oracles.beta))) *
        &(&lagrange.d8.this.r + &(l0 + &self.l1.scale(oracles.beta * &self.r)))) *
        &(&lagrange.d8.this.o + &(l0 + &self.l1.scale(oracles.beta * &self.o)))) *
        &lagrange.d8.this.z)
        -
        &(&(&(&(&lagrange.d8.this.l + &(l0 + &self.sigmal4[0].scale(oracles.beta))) *
        &(&lagrange.d8.this.r + &(l0 + &self.sigmal4[1].scale(oracles.beta)))) *
        &(&lagrange.d8.this.o + &(l0 + &self.sigmal4[2].scale(oracles.beta)))) *
        &lagrange.d8.next.z)).scale(oracles.alpha)
    }

    pub fn perm_lnrz(&self, e: &Vec<ProofEvaluations<F>>, oracles: &RandomOracles<F>) -> DensePolynomial<F>
    {
        self.sigmam[2].scale(Self::perm_scalars(e, oracles)[0] * &oracles.beta)
    }

    // permutation linearization poly contribution computation
    pub fn perm_scalars(e: &Vec<ProofEvaluations<F>>, oracles: &RandomOracles<F>) -> Vec<F>
    {
        vec!
        [
            (e[0].l + &(oracles.beta * &e[0].sigma1) + &oracles.gamma) *
            &(e[0].r + &(oracles.beta * &e[0].sigma2) + &oracles.gamma) *
            &(e[1].z * &oracles.alpha)
        ]
    }
}
