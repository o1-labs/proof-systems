/*****************************************************************************************************************

This source file implements permutation constraint polynomial.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use crate::scalars::{ProofEvaluations, RandomOracles};
use crate::polynomial::WitnessOverDomains;
use oracle::utils::{EvalUtils, PolyUtils};
use crate::constraints::ConstraintSystem;
use crate::wires::COLUMNS;

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

        &(&lagrange.d8.this.w.iter().zip(self.shift.iter()).
            map(|(p, s)| p + &(l0 + &self.l1.scale(oracles.beta * s))).
            fold(lagrange.d8.this.z.clone(), |x, y| &x * &y)
        -
        &lagrange.d8.this.w.iter().zip(self.sigmal8.iter()).
            map(|(p, s)| p + &(l0 + &s.scale(oracles.beta))).
            fold(lagrange.d8.next.z.clone(), |x, y| &x * &y)).
        scale(oracles.alpha)
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
            &self.shift,
            alpha,
            self.domain.d1.size,
            self.zkpm.evaluate(oracles.zeta),
            self.sid[self.domain.d1.size as usize -3]
        );
        &z.scale(scalars[0]) + &self.sigmam[COLUMNS-1].scale(scalars[1])
    }

    // permutation linearization poly contribution computation
    pub fn perm_scalars
    (
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        shift: &[F; COLUMNS],
        alpha: &[F],
        n: u64,
        z: F,
        w: F,
    ) -> Vec<F>
    {
        let bz = oracles.beta * &oracles.zeta;
        vec!
        [
            e[0].w.iter().zip(shift.iter()).
                map(|(w, s)| oracles.gamma + &(bz * s) + w).
                fold(oracles.alpha * &z, |x, y| x * y) +
            &(alpha[0] * &(oracles.zeta.pow(&[n]) - &F::one()) / &(oracles.zeta - &F::one())) +
            &(alpha[1] * &(oracles.zeta.pow(&[n]) - &F::one()) / &(oracles.zeta - &w))
            ,
            -e[0].w.iter().zip(e[0].s.iter()).
                map(|(w, s)| oracles.gamma + &(oracles.beta * s) + w).
                fold(e[1].z * &oracles.beta * &oracles.alpha * &z, |x, y| x * y)
        ]
    }
}
