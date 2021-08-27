/*****************************************************************************************************************

This source file implements permutation constraint polynomials.

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::{ProofEvaluations, RandomOracles};
use crate::polynomial::WitnessOverDomains;
use crate::wires::*;
use algebra::{FftField, SquareRootField};
use ff_fft::{
    DenseOrSparsePolynomial, DensePolynomial, EvaluationDomain, Evaluations,
    Radix2EvaluationDomain as D,
};
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
        let one_poly = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let z_minus_1 = z - &one_poly;

        // TODO(mimoo): use self.sid[0] instead of 1
        // accumulator init := (z(x) - 1) / (x - 1)
        let x_minus_1 = DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]);
        let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &z_minus_1.clone().into(),
            &x_minus_1.clone().into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        // accumulator end := (z(x) - 1) / (x - sid[n-3])
        let denominator = DensePolynomial::from_coefficients_slice(&[
            -self.sid[self.domain.d1.size as usize - 3],
            F::one(),
        ]);
        let (bnd2, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&z_minus_1.into(), &denominator.into())
                .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        // shifts = z(x) *
        // (w[0](x) + gamma + x * beta * shift[0]) *
        // (w[1](x) + gamma + x * beta * shift[1]) * ...
        // (w[6](x) + gamma + x * beta * shift[6])
        // in evaluation form in d8
        let mut shifts = lagrange.d8.this.z.clone();
        for (witness, shift) in lagrange.d8.this.w.iter().zip(self.shift.iter()) {
            let term = &(witness + gamma) + &self.l1.scale(oracles.beta * shift);
            shifts = &shifts * &term;
        }

        // sigmas = z(x * w) *
        // (w8[0] + gamma + sigma[0] * beta) *
        // (w8[1] + gamma + sigma[1] * beta) * ...
        // (w8[6] + gamma + sigma[6] * beta)
        // in evaluation form in d8
        let mut sigmas = lagrange.d8.next.z.clone();
        for (witness, sigma) in lagrange.d8.this.w.iter().zip(self.sigmal8.iter()) {
            let term = witness + &(gamma + &sigma.scale(oracles.beta));
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
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        let zkpm_zeta = self.zkpm.evaluate(oracles.zeta);
        let scalar = Self::perm_scalars(e, oracles, alpha, zkpm_zeta);
        self.sigmam[PERMUTS - 1].scale(scalar)
    }

    pub fn perm_scalars(
        e: &Vec<ProofEvaluations<F>>,
        oracles: &RandomOracles<F>,
        // TODO(mimoo): should only pass an iterator, to prevent different calls to re-use the same alphas!
        alpha: &[F],
        zkp_zeta: F,
    ) -> F {
        -e[0]
            .w
            .iter()
            .zip(e[0].s.iter())
            .map(|(w, s)| oracles.gamma + &(oracles.beta * s) + w)
            .fold(e[1].z * &oracles.beta * alpha[0] * &zkp_zeta, |x, y| x * y)
        /* TODO(mimoo): refactor with this when test pass
        // we only use PERMUTATIONS-1 sigmas, as the last one is used later as a polynomial
        let sigmas = e[0].s.iter();
        // - z(zeta * omega) * beta * alpha^PERM0 * zkp(zeta)
        let mut res = -alpha[0] * e[1].z * &oracles.beta * zkp_zeta;
        for (witness_zeta, sigma_zeta) in e[0].w.iter().zip(sigmas) {
            // * (gamma + beta * sigma_i(zeta) + w_i(zeta))
            res *= oracles.gamma + oracles.beta * sigma_zeta + witness_zeta
        }
        res
        */
    }

    /// permutation aggregation polynomial computation
    pub fn perm_aggreg(
        &self,
        witness: &[Vec<F>; COLUMNS],
        oracles: &RandomOracles<F>,
        rng: &mut ThreadRng,
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

        // fill last k entries with randomness
        z[n - 2] = F::rand(rng);
        z[n - 1] = F::rand(rng);

        let res = Evaluations::<F, D<F>>::from_vec_and_domain(z, self.domain.d1).interpolate();
        Ok(res)
    }

    /// verify permutation
    #[cfg(test)]
    pub fn verify_perm(
        &self,
        lagrange: &WitnessOverDomains<F>,
        oracles: &RandomOracles<F>,
        z: &DensePolynomial<F>,
        alpha: &[F],
    ) -> Result<(Evaluations<F, D<F>>, DensePolynomial<F>), ProofError> {
        // constant gamma in evaluation form (in domain d8)
        let gamma = &self.l08.scale(oracles.gamma);
        let one_poly = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let z_minus_1 = z - &one_poly;

        // TODO(mimoo): use self.sid[0] instead of 1
        // accumulator init := (z(x) - 1) / (x - 1)
        let x_minus_1 = DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]);
        let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &z_minus_1.clone().into(),
            &x_minus_1.clone().into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        // accumulator end := (z(x) - 1) / (x - sid[n-3])
        let denominator = DensePolynomial::from_coefficients_slice(&[
            -self.sid[self.domain.d1.size as usize - 3],
            F::one(),
        ]);
        let (bnd2, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&z_minus_1.into(), &denominator.into())
                .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        // shifts = z(x) *
        // (w[0](x) + gamma + x * beta * shift[0]) *
        // (w[1](x) + gamma + x * beta * shift[1]) * ...
        // (w[6](x) + gamma + x * beta * shift[6])
        // in evaluation form in d8
        let mut shifts = lagrange.d8.this.z.clone();
        for (witness, shift) in lagrange.d8.this.w.iter().zip(self.shift.iter()) {
            let term = &(witness + gamma) + &self.l1.scale(oracles.beta * shift);
            shifts = &shifts * &term;
        }

        // sigmas = z(x * w) *
        // (w8[0] + gamma + sigma[0] * beta) *
        // (w8[1] + gamma + sigma[1] * beta) * ...
        // (w8[6] + gamma + sigma[6] * beta)
        // in evaluation form in d8
        let mut sigmas = lagrange.d8.next.z.clone();
        for (witness, sigma) in lagrange.d8.this.w.iter().zip(self.sigmal8.iter()) {
            let term = witness + &(gamma + &sigma.scale(oracles.beta));
            sigmas = &sigmas * &term;
        }

        let perm = &(&shifts - &sigmas).scale(alpha[0]) * &self.zkpl;
        let bnd = &bnd1.scale(alpha[1]) + &bnd2.scale(alpha[2]);

        // test if every evaluation in the domain of the perm is zero
        let x_n_minus_1: DensePolynomial<F> = self.domain.d1.vanishing_polynomial().into();

        {
            // testing lagrange base first first

            let base = x_n_minus_1.scale(self.domain.d1.size_inv); // (x^n-1)/n
            let base: DenseOrSparsePolynomial<F> = base.into();
            let x_minus_1: DenseOrSparsePolynomial<_> = x_minus_1.into();
            let (base, rem) = base.divide_with_q_and_r(&x_minus_1).unwrap(); // (x^n-1)/n(x-1)

            if !rem.is_zero() {
                panic!(" wtf??? {:?}", rem);
            }

            for (idx, elem) in self.domain.d1.elements().enumerate() {
                let res = base.evaluate(elem);
                if idx == 0 && res != F::one() {
                    panic!("holy shit batman: superman is here");
                }
                if idx > 0 && !res.is_zero() {
                    panic!("holy shit batman");
                }
            }
        }

        let perm_test = (&shifts - &sigmas).interpolate();
        let perm_test = &perm_test * &self.zkpl.interpolate_by_ref();
        let bnd2_test = bnd2.scale(crate::nolookup::constraints::zk_w3(self.domain.d1));
        let bnd2_test = &bnd2_test * &x_n_minus_1;
        let bnd2_test = bnd2_test.scale(self.domain.d1.size_inv);

        let bnd1_test = bnd1.scale(self.domain.d1.size_inv); // (z(x)-1)/n(x-1)
        let bnd1_test = &bnd1_test * &x_n_minus_1; // (z(x)-1)(z^n-1)/n(x-1)

        // easy test first
        let first = self.domain.d1.elements().next().unwrap();
        if z.evaluate(first) != F::one() {
            panic!("holy shit batman");
        }
        if z.evaluate(self.sid[(self.domain.d1.size - 3) as usize]) != F::one() {
            panic!("hole shit batman: the sequel");
        }

        // all domain
        for (row, elem) in ff_fft::EvaluationDomain::elements(&self.domain.d1).enumerate() {
            let vv = perm_test.evaluate(elem);
            if !vv.is_zero() {
                panic!("row {} has perm evaluation different from zero", row);
            }

            let b1 = bnd1_test.evaluate(elem);
            if !b1.is_zero() {
                panic!("row {} has bnd1 evaluation different from zero", row);
            }

            let b2 = bnd2_test.evaluate(elem);
            if !b2.is_zero() {
                panic!("row {} has bnd2 evaluation different from zero", row);
            }
        }

        // test if perm can be divided by vanishing polynomial (delete once it does)
        let (_, res) = perm_test.divide_by_vanishing_poly(self.domain.d1).unwrap();
        if !res.is_zero() {
            panic!("perm_quot failed");
        }

        //
        Ok((perm, bnd))
    }
}
