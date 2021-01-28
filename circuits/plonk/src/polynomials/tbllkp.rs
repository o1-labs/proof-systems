/*****************************************************************************************************************

This source file implements table loopup polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D, DenseOrSparsePolynomial};
use oracle::{utils::{EvalUtils, PolyUtils}, rndoracle::ProofError};
use crate::constraints::ConstraintSystem;
use crate::scalars::RandomOracles;
use crate::wires::COLUMNS;

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    // lookup quotient poly contribution computation
    pub fn tbllkp_quot
    (
        &self,
        (lw, h1, h2): (&DensePolynomial<F>, &DensePolynomial<F>, &DensePolynomial<F>),
        oracles: &RandomOracles<F>,
        l: &DensePolynomial<F>,
        alpha: &[F]
    ) -> Result<(Evaluations<F, D<F>>, DensePolynomial<F>), ProofError>
    {
        let n = self.domain.d1.size as usize;

        let (bnd1, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(l - &DensePolynomial::from_coefficients_slice(&[F::one()]).scale(alpha[1])).into(),
                &DensePolynomial::from_coefficients_slice(&[-F::one(), F::one()]).into()).
                    map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        let h2w = DensePolynomial::from_coefficients_slice(&h2.coeffs.iter().
            zip(self.sid.iter()).map(|(z, w)| *z * w).collect::<Vec<_>>());
        let (bnd2, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&(l - &DensePolynomial::from_coefficients_slice(&[F::one()])).scale(alpha[2]) +
                    &(h1 - &h2w).scale(alpha[3])).into(),
                &DensePolynomial::from_coefficients_slice(&[-self.sid[n-1], F::one()]).into()).
                    map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        let lw = lw.evaluate_over_domain_by_ref(self.domain.d4);
        let ll = l.evaluate_over_domain_by_ref(self.domain.d4);
        let llw = ll.shift(4);
        let h1l = h1.evaluate_over_domain_by_ref(self.domain.d4);
        let h1lw = h1l.shift(4);
        let h2l = h2.evaluate_over_domain_by_ref(self.domain.d4);
        let h2lw = h2l.shift(4);

        let beta1 = F::one() + oracles.beta2;
        let gammabeta1 = &self.l04.scale(beta1 * oracles.gamma2);

        Ok((
            (&(&(&(&ll.scale(beta1) *
                &(&self.l04.scale(oracles.gamma2) + &lw)) *
                &(gammabeta1 + &(&self.table4 + &self.table4w.scale(oracles.beta2))))
            -
            &(&(&llw *
                &(gammabeta1 + &(&h1l + &h1lw.scale(oracles.beta2)))) *
                &(gammabeta1 + &(&h2l + &h2lw.scale(oracles.beta2)))))
            *
            &(&self.l14 - &self.l04.scale(self.sid[n-1]))).
            scale(alpha[0])
            ,
            &bnd1 + &bnd2
        ))
    }

    // lookup sorted set computation
    pub fn tbllkp_sortedset
    (
        &self,
        witness: &[Vec::<F>; COLUMNS],
    ) -> (Vec<F>, Vec<F>, Vec<F>)
    {
        let n = self.domain.d1.size as usize;
        // get lookup values
        let lw = witness[COLUMNS-1].iter().take(n-1).zip(self.gates.iter()).
            map(|(w, g)| g.lookup() * w).collect::<Vec<_>>();
        let mut s = lw.clone();
        s.extend(self.table1.evals.clone());

        // sort s by the table
        s.sort_unstable_by(|x, y| {self.table1.evals.iter().position(|t| x == t).unwrap().
            cmp(&self.table1.evals.iter().position(|t| y == t).unwrap())});

        let mut h = vec![s[n-1]];
        h.append(&mut s.drain(n..2*n-1).collect());
        (lw, s, h)
    }

    // lookup aggregation polynomial computation
    pub fn tbllkp_aggreg
    (
        &self,
        (lw, h1, h2): (Vec<F>, Vec<F>, Vec<F>),
        oracles: &RandomOracles<F>
    ) -> Result<DensePolynomial<F>, ProofError>
    {
        let n = self.domain.d1.size as usize;
        let beta1 = F::one() + oracles.beta2;
        let gammabeta1 = beta1 * oracles.gamma2;
        let mut z = vec![F::one(); n];
        (0..n-1).for_each
        (
            |j| z[j+1] =
                (gammabeta1 + h1[j] + (oracles.beta2 * h1[j+1])) *
                (gammabeta1 + h2[j] + (oracles.beta2 * h2[j+1]))
        );
        algebra::fields::batch_inversion::<F>(&mut z[1..=n]);
        (0..n-1).for_each
        (
            |j|
            {
                let x = z[j];
                z[j+1] *= &(x * beta1 * (oracles.gamma2 + lw[j]) *
                    (gammabeta1 + self.table1.evals[j] + (oracles.beta2 * self.table1.evals[j+1])))
            }
        );

        if z[n-1] != F::one() {return Err(ProofError::ProofCreation)};
        Ok(Evaluations::<F, D<F>>::from_vec_and_domain(z, self.domain.d1).interpolate())
    }
}
