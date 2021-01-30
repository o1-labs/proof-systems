/*****************************************************************************************************************

This source file implements table loopup polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use crate::polynomial::{LookupEvals, LookupPolys};
use ff_fft::{Evaluations as E, DensePolynomial as DP, Radix2EvaluationDomain as D, DenseOrSparsePolynomial, EvaluationDomain};
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
        lkppolys: &LookupPolys<F>,
        oracles: &RandomOracles<F>,
        alpha: &[F]
    ) -> Result<(E<F, D<F>>, DP<F>), ProofError>
    {
        let n = self.domain.d1.size as usize;

        let (bnd1, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&lkppolys.l - &DP::from_coefficients_slice(&[F::one()])).scale(alpha[1]).into(),
                &DP::from_coefficients_slice(&[-F::one(), F::one()]).into()).
                    map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        let h2w = DP::from_coefficients_slice(&lkppolys.h2.coeffs.iter().
            zip(self.sid.iter()).map(|(z, w)| *z * w).collect::<Vec<_>>());
        let (bnd2, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&(&lkppolys.l - &DP::from_coefficients_slice(&[F::one()])).scale(alpha[2]) +
                    &(&lkppolys.h1 - &h2w).scale(alpha[3])).into(),
                &DP::from_coefficients_slice(&[-self.sid[n-1], F::one()]).into()).
                    map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        let evals = self.evaluate2(lkppolys);
        let beta1 = F::one() + oracles.beta2;
        let gammabeta1 = &self.l04.scale(beta1 * oracles.gamma2);

        Ok((
            (&(&(&(&evals.this.l.scale(beta1) *
                &(&self.l04.scale(oracles.gamma2) + &evals.this.lw)) *
                &(gammabeta1 + &(&self.table4 + &self.table4w.scale(oracles.beta2))))
            -
            &(&(&evals.next.l *
                &(gammabeta1 + &(&evals.this.h1 + &evals.next.h1.scale(oracles.beta2)))) *
                &(gammabeta1 + &(&evals.this.h2 + &evals.next.h2.scale(oracles.beta2)))))
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
    ) -> LookupEvals<F>
    {
        let n = self.domain.d1.size as usize;
        // get lookup values
        let lw = witness[COLUMNS-1].iter().take(n-1).zip(self.gates.iter()).
            map(|(w, g)| g.lookup() * w).collect::<Vec<_>>();
        let mut s = lw.clone();
        s.extend(self.table1.evals.clone());

        // sort s by the table
        s.sort_unstable_by
        (
            |x, y|
            {
                match (self.table1.evals.iter().position(|t| x == t), self.table1.evals.iter().position(|t| y == t))
                {
                    (Some(p1), Some(p2)) => p1.cmp(&p2),
                    _ => panic!("table lookup failure")
                }
            }
        );

        let mut h = vec![s[n-1]];
        h.append(&mut s.drain(n..2*n-1).collect());
        LookupEvals
        {
            l: DP::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap()),
            lw: E::<F, D<F>>::from_vec_and_domain(lw, self.domain.d1),
            h1: E::<F, D<F>>::from_vec_and_domain(s, self.domain.d1),
            h2: E::<F, D<F>>::from_vec_and_domain(h, self.domain.d1),
        }
    }

    // lookup aggregation polynomial computation
    pub fn tbllkp_aggreg
    (
        &self,
        lkpevl: &mut LookupEvals<F>,
        oracles: &RandomOracles<F>
    ) -> Result<DP<F>, ProofError>
    {
        let n = self.domain.d1.size as usize;
        let beta1 = F::one() + oracles.beta2;
        let gammabeta1 = beta1 * oracles.gamma2;
        let mut z = vec![F::one(); n];
        (0..n-1).for_each
        (
            |j| z[j+1] =
                (gammabeta1 + lkpevl.h1.evals[j] + (oracles.beta2 * lkpevl.h1.evals[j+1])) *
                (gammabeta1 + lkpevl.h2.evals[j] + (oracles.beta2 * lkpevl.h2.evals[j+1]))
        );
        algebra::fields::batch_inversion::<F>(&mut z[1..n]);
        (0..n-1).for_each
        (
            |j|
            {
                let x = z[j];
                z[j+1] *= &(x * beta1 * (oracles.gamma2 + lkpevl.lw.evals[j]) *
                    (gammabeta1 + self.table1.evals[j] + (oracles.beta2 * self.table1.evals[j+1])))
            }
        );

        if z[n-1] != F::one() {return Err(ProofError::ProofCreation)};
        lkpevl.l = E::<F, D<F>>::from_vec_and_domain(z, self.domain.d1);
        Ok(lkpevl.l.interpolate_by_ref())
    }
}
