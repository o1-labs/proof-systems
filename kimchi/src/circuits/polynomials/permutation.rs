//! This module implements permutation constraint polynomials.

use crate::circuits::{
    constraints::ConstraintSystem, polynomial::WitnessOverDomains, scalars::ProofEvaluations,
    wires::*,
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use ark_poly::{Polynomial, UVPolynomial};
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use oracle::rndoracle::ProofError;
use rand::{CryptoRng, RngCore};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// permutation quotient poly contribution computation
    #[allow(clippy::type_complexity)]
    pub fn perm_quot(
        &self,
        lagrange: &WitnessOverDomains<F>,
        beta: F,
        gamma: F,
        z: &DensePolynomial<F>,
        alpha: &[F],
    ) -> Result<(Evaluations<F, D<F>>, DensePolynomial<F>), ProofError> {
        // constant gamma in evaluation form (in domain d8)
        let gamma = &self.l08.scale(gamma);
        let one_poly = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let z_minus_1 = z - &one_poly;

        // TODO(mimoo): use self.sid[0] instead of 1
        // accumulator init := (z(x) - 1) / (x - 1)
        let x_minus_1 = DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]);
        let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &z_minus_1.clone().into(),
            &x_minus_1.into(),
        )
        .map_or(Err(ProofError::PolyDivision), Ok)?;
        if !res.is_zero() {
            return Err(ProofError::PolyDivision);
        }

        // accumulator end := (z(x) - 1) / (x - sid[n-3])
        let denominator = DensePolynomial::from_coefficients_slice(&[
            -self.sid[self.domain.d1.size as usize - 3],
            F::one(),
        ]);
        let (bnd2, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&z_minus_1.into(), &denominator.into())
                .map_or(Err(ProofError::PolyDivision), Ok)?;
        if !res.is_zero() {
            return Err(ProofError::PolyDivision);
        }

        // shifts = z(x) *
        // (w[0](x) + gamma + x * beta * shift[0]) *
        // (w[1](x) + gamma + x * beta * shift[1]) * ...
        // (w[6](x) + gamma + x * beta * shift[6])
        // in evaluation form in d8
        let mut shifts = lagrange.d8.this.z.clone();
        for (witness, shift) in lagrange.d8.this.w.iter().zip(self.shift.iter()) {
            let term = &(witness + gamma) + &self.l1.scale(beta * shift);
            shifts = &shifts * &term;
        }

        // sigmas = z(x * w) *
        // (w8[0] + gamma + sigma[0] * beta) *
        // (w8[1] + gamma + sigma[1] * beta) * ...
        // (w8[6] + gamma + sigma[6] * beta)
        // in evaluation form in d8
        let mut sigmas = lagrange.d8.next.z.clone();
        for (witness, sigma) in lagrange.d8.this.w.iter().zip(self.sigmal8.iter()) {
            let term = witness + &(gamma + &sigma.scale(beta));
            sigmas = &sigmas * &term;
        }

        let perm = &(&shifts - &sigmas).scale(alpha[0]) * &self.zkpl;
        let bnd = &bnd1.scale(alpha[1]) + &bnd2.scale(alpha[2]);

        //
        Ok((perm, bnd))
    }

    /// permutation linearization poly contribution computation
    pub fn perm_lnrz(
        &self,
        e: &[ProofEvaluations<F>],
        zeta: F,
        beta: F,
        gamma: F,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        let zkpm_zeta = self.zkpm.evaluate(&zeta);
        let scalar = Self::perm_scalars(e, beta, gamma, alpha, zkpm_zeta);
        self.sigmam[PERMUTS - 1].scale(scalar)
    }

    pub fn perm_scalars(
        e: &[ProofEvaluations<F>],
        beta: F,
        gamma: F,
        // TODO(mimoo): should only pass an iterator, to prevent different calls to re-use the same alphas!
        alpha: &[F],
        zkp_zeta: F,
    ) -> F {
        -e[0]
            .w
            .iter()
            .zip(e[0].s.iter())
            .map(|(w, s)| gamma + (beta * s) + w)
            .fold(e[1].z * beta * alpha[0] * zkp_zeta, |x, y| x * y)
    }

    /// permutation aggregation polynomial computation
    pub fn perm_aggreg(
        &self,
        witness: &[Vec<F>; COLUMNS],
        beta: &F,
        gamma: &F,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DensePolynomial<F>, ProofError> {
        let n = self.domain.d1.size as usize;

        // only works if first element is 1
        assert!(self.domain.d1.elements().next() == Some(F::one()));

        // initialize accumulator at 1
        let mut z = vec![F::one(); n];

        // z[j+1] = [
        //           (w[0][j] + sid[j] * beta * shift[0] + gamma) *
        //           (w[1][j] + sid[j] * beta * shift[1] + gamma) *
        //           ... *
        //           (w[6][j] + sid[j] * beta * shift[6] + gamma)
        //          ] / [
        //           (w[0][j] + sigma[0] * beta + gamma) *
        //           (w[1][j] + sigma[1] * beta + gamma) *
        //           ... *
        //           (w[6][j] + sigma[6] * beta + gamma)
        //          ]
        //
        // except for the first element (initialized at 1),
        // and the last k elements for zero-knowledgness
        for j in 0..n - 3 {
            z[j + 1] = witness
                .iter()
                .zip(self.sigmal1.iter())
                .map(|(w, s)| w[j] + (s[j] * beta) + gamma)
                .fold(F::one(), |x, y| x * y)
        }

        ark_ff::fields::batch_inversion::<F>(&mut z[1..=n - 3]);

        for j in 0..n - 3 {
            let x = z[j];
            z[j + 1] *= witness
                .iter()
                .zip(self.shift.iter())
                .map(|(w, s)| w[j] + (self.sid[j] * beta * s) + gamma)
                .fold(x, |z, y| z * y)
        }

        // check that last accumulator entry is 1
        if z[n - 3] != F::one() {
            return Err(ProofError::ProofCreation);
        };

        // fill last k entries with randomness
        z[n - 2] = F::rand(rng);
        z[n - 1] = F::rand(rng);

        let res = Evaluations::<F, D<F>>::from_vec_and_domain(z, self.domain.d1).interpolate();
        Ok(res)
    }
}
