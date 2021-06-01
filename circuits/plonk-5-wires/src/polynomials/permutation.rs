/*****************************************************************************************************************

This source file implements permutation constraint polynomial.

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::{ProofEvaluations, RandomOracles};
use crate::wires::COLUMNS;
use algebra::{FftField, SquareRootField};
use ark_poly::{
    DenseOrSparsePolynomial, DensePolynomial, Evaluations, Radix2EvaluationDomain as D,
};
use oracle::{
    rndoracle::ProofError,
    utils::{EvalUtils, PolyUtils},
};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // permutation quotient poly contribution computation
    pub fn perm_quot(
        &self,
        lagrange: &WitnessOverDomains<F>,
        oracles: &RandomOracles<F>,
        z: &DensePolynomial<F>,
        alpha: &[F],
    ) -> Result<(Evaluations<F, D<F>>, DensePolynomial<F>), ProofError> {
        let l0 = &self.l08.scale(oracles.gamma);

        let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &(z - &DensePolynomial::from_coefficients_slice(&[F::one()])).into(),
            &DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]).into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        let (bnd2, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &(z - &DensePolynomial::from_coefficients_slice(&[F::one()])).into(),
            &DensePolynomial::from_coefficients_slice(&[
                -self.sid[self.domain.d1.size as usize - 3],
                F::one(),
            ])
            .into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        Ok((
            &(&lagrange
                .d8
                .this
                .w
                .iter()
                .zip(self.shift.iter())
                .map(|(p, s)| p + &(l0 + &self.l1.scale(oracles.beta * s)))
                .fold(lagrange.d8.this.z.clone(), |x, y| &x * &y)
                - &lagrange
                    .d8
                    .this
                    .w
                    .iter()
                    .zip(self.sigmal8.iter())
                    .map(|(p, s)| p + &(l0 + &s.scale(oracles.beta)))
                    .fold(lagrange.d8.next.z.clone(), |x, y| &x * &y))
                .scale(oracles.alpha)
                * &self.zkpl,
            &bnd1.scale(alpha[0]) + &bnd2.scale(alpha[1]),
        ))
    }

    // permutation linearization poly contribution computation
    pub fn perm_lnrz(
        &self,
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
    ) -> DensePolynomial<F> {
        self.sigmam[COLUMNS - 1].scale(Self::perm_scalars(
            e,
            oracles,
            self.zkpm.evaluate(oracles.zeta),
        ))
    }

    pub fn perm_scalars(e: &Vec<ProofEvaluations<F>>, oracles: &RandomOracles<F>, z: F) -> F {
        -e[0]
            .w
            .iter()
            .zip(e[0].s.iter())
            .map(|(w, s)| oracles.gamma + &(oracles.beta * s) + w)
            .fold(e[1].z * &oracles.beta * &oracles.alpha * &z, |x, y| x * y)
    }
}
