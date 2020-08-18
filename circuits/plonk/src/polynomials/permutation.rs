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

    pub fn perm_lnrz
    (
        &self, e: &Vec<ProofEvaluations<F>>,
        z: &DensePolynomial<F>,
        oracles: &RandomOracles<F>
    ) -> DensePolynomial<F>
    {
        let scalars = Self::perm_scalars(e, oracles, (self.r, self.o), self.domain.d1.size);
        &z.scale(scalars[0]) + &self.sigmam[2].scale(scalars[1])
    }

    // permutation linearization poly contribution computation
    pub fn perm_scalars
    (
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        shift: (F, F),
        n: u64,
    ) -> Vec<F>
    {
        let bz = oracles.beta * &oracles.zeta;
        vec!
        [
            (e[0].l + &bz + &oracles.gamma) *
            &(e[0].r + &(bz * &shift.0) + &oracles.gamma) *
            &(e[0].o + &(bz * &shift.1) + &oracles.gamma) *
            &oracles.alpha +
            &(oracles.alpha.square() * &(oracles.zeta.pow(&[n]) - &F::one()) / &(oracles.zeta - &F::one()))
            ,
            -(e[0].l + &(oracles.beta * &e[0].sigma1) + &oracles.gamma) *
            &(e[0].r + &(oracles.beta * &e[0].sigma2) + &oracles.gamma) *
            &(e[1].z * &oracles.beta * &oracles.alpha)
        ]
    }
}
