/*****************************************************************************************************************

This source file implements permutation constraint polynomials.

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::{ProofEvaluations, RandomOracles};
use crate::polynomial::WitnessOverDomains;
use crate::wires::*;
use algebra::{FftField, SquareRootField};
use ff_fft::{DenseOrSparsePolynomial, DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::{
    rndoracle::ProofError,
    utils::{EvalUtils, PolyUtils},
};
use rand::rngs::ThreadRng;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// permutation quotient poly contribution computation
    pub fn perm_quot(
        &self,
        lagrange: &WitnessOverDomains<F>,
        oracles: &RandomOracles<F>,
        z: &DensePolynomial<F>,
        alpha: &[F],
    ) -> Result<(Evaluations<F, D<F>>, DensePolynomial<F>), ProofError> {
        // constant gamma in evaluation form (in domain d8)
        let gamma = &self.l08.scale(oracles.gamma);

        // TODO(mimoo): use self.sid[0] instead of 1
        // accumulator init := (z(x) - 1) / (x - 1)
        let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &(z - &DensePolynomial::from_coefficients_slice(&[F::one()])).into(),
            &DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]).into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        // accumulator end := (z(x) - 1) / (x - sid[n-3])
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

        // shifts = z(x) *
        // (w[0](x) + gamma + x * beta * shift[0]) *
        // (w[1](x) + gamma + x * beta * shift[1]) * ...
        // in evaluation form in d8
        let mut shifts = lagrange.d8.this.z.clone();
        for (witness, shift) in lagrange.d8.this.w.iter().zip(self.shift.iter()) {
            let term = &(witness + gamma) + &self.l1.scale(oracles.beta * shift);
            shifts = &shifts * &term;
        }

        // sigmas = z(x * w) *
        // (w8[0] + gamma + sigma[0] * beta) *
        // (w8[1] + gamma + sigma[1] * beta) * ...
        // in evaluation form in d8
        let mut sigmas = lagrange.d8.next.z.clone();
        for (witness, sigma) in lagrange.d8.this.w.iter().zip(self.sigmal8.iter()) {
            let term = witness + &(gamma + &sigma.scale(oracles.beta));
            sigmas = &sigmas * &term;
        }

        let perm = &(&shifts - &sigmas).scale(alpha[0]) * &self.zkpl;

        Ok((perm, &bnd1.scale(alpha[1]) + &bnd2.scale(alpha[2])))
    }

    /// permutation linearization poly contribution computation
    pub fn perm_lnrz(
        &self,
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        self.sigmam[PERMUTS - 1].scale(Self::perm_scalars(
            e,
            oracles,
            alpha,
            self.zkpm.evaluate(oracles.zeta),
        ))
    }

    pub fn perm_scalars(
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        // TODO(mimoo): should only pass an iterator, to prevent different calls to re-use the same alphas!
        alpha: &[F],
        z: F,
    ) -> F {
        -e[0]
            .w
            .iter()
            .zip(e[0].s.iter())
            .map(|(w, s)| oracles.gamma + &(oracles.beta * s) + w)
            .fold(e[1].z * &oracles.beta * alpha[0] * &z, |x, y| x * y)
    }

    /// permutation aggregation polynomial computation
    pub fn perm_aggreg(
        &self,
        witness: &[Vec<F>; COLUMNS],
        oracles: &RandomOracles<F>,
        rng: &mut ThreadRng,
    ) -> Result<DensePolynomial<F>, ProofError> {
        let n = self.domain.d1.size as usize;

        // initialize accumulator at 1
        let mut z = vec![F::one(); n];

        // z[j+1] = [
        //           (w[0][j] + sid[j] * beta * shift[0] + gamma) *
        //           (w[1][j] + sid[j] * beta * shift[1] + gamma) *
        //           ... *
        //           (w[14][j] + sid[j] * beta * shift[14] + gamma)
        //          ] / [
        //           (w[0][j] + sigma[0] * beta + gamma) *
        //           (w[1][j] + sigma[1] * beta + gamma) *
        //           ... *
        //           (w[14][j] + sigma[14] * beta + gamma)
        //          ]
        //
        // except for the first element (initialized at 1),
        // and the last k elements for zero-knowledgness
        for j in 0..n - 3 {
            z[j + 1] = witness
                .iter()
                .zip(self.sigmal1.iter())
                .map(|(w, s)| w[j] + &(s[j] * &oracles.beta) + &oracles.gamma)
                .fold(F::one(), |x, y| x * y)
        }

        algebra::fields::batch_inversion::<F>(&mut z[1..=n - 3]);

        for j in 0..n - 3 {
            let x = z[j];
            z[j + 1] *= witness
                .iter()
                .zip(self.shift.iter())
                .map(|(w, s)| w[j] + &(self.sid[j] * &oracles.beta * s) + &oracles.gamma)
                .fold(x, |z, y| z * y)
        }

        // check that last accumulator entry is 1
        if z[n - 3] != F::one() {
            return Err(ProofError::ProofCreation);
        };

        // fill last two entries with randomness
        z[n - 2] = F::rand(rng);
        z[n - 1] = F::rand(rng);
        Ok(Evaluations::<F, D<F>>::from_vec_and_domain(z, self.domain.d1).interpolate())
    }
}
