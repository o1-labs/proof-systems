/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, DensePolynomial, Radix2EvaluationDomain as D};
use oracle::{utils::{PolyUtils, EvalUtils}, poseidon::{PlonkSpongeConstants,sbox, ArithmeticSpongeParams}};
use crate::polynomial::WitnessOverDomains;
use crate::constraints::ConstraintSystem;
use crate::scalars::ProofEvaluations;

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    // poseidon quotient poly contribution computation f^5 + c(x) - f(wx)
    pub fn psdn_quot
    (
        &self, polys: &WitnessOverDomains<F>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &Vec<F>
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>, DensePolynomial<F>)
    {
        if self.psm.is_zero() {return (self.ps4.clone(), self.ps8.clone(), DensePolynomial::<F>::zero())}

        let mut lro = [polys.d8.this.l.clone(), polys.d8.this.r.clone(), polys.d8.this.o.clone()];
        lro.iter_mut().for_each(|p| p.evals.iter_mut().for_each(|p| *p = sbox::<F, PlonkSpongeConstants>(*p)));

        let scalers = (0..params.mds.len()).
            map(|i| (0..params.mds[i].len()).fold(F::zero(), |x, j| alpha[j+1] * params.mds[j][i] + x)).
            collect::<Vec<_>>();

        (
            &self.ps4 * &(&(&polys.d4.next.l.scale(-alpha[1]) - &polys.d4.next.r.scale(alpha[2])) - &polys.d4.next.o.scale(alpha[3])),
            &self.ps8 * &(&(&lro[0].scale(scalers[0]) + &lro[1].scale(scalers[1])) + &lro[2].scale(scalers[2])),
            &(&self.rcm[0].scale(alpha[1]) + &self.rcm[1].scale(alpha[2])) + &self.rcm[2].scale(alpha[3])
        )
    }

    pub fn psdn_scalars
    (
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &Vec<F>
    ) -> Vec<F>
    {
        let lro = params.mds.iter().
            map
            (
                |m|
                [
                    sbox::<F, PlonkSpongeConstants>(evals[0].l),
                    sbox::<F, PlonkSpongeConstants>(evals[0].r),
                    sbox::<F, PlonkSpongeConstants>(evals[0].o)
                ].iter().zip(m.iter()).fold(F::zero(), |x, (s, &m)| m * s + x)).collect::<Vec<_>>();

        vec!
        [
            (0..lro.len()).fold(F::zero(), |x, i| x + alpha[i+1] * (lro[i] - [evals[1].l, evals[1].r, evals[1].o][i])),
            alpha[1],
            alpha[2],
            alpha[3]
        ]
    }

    // poseidon linearization poly contribution computation f^5 + c(x) - f(wx)
    pub fn psdn_lnrz
    (
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &Vec<F>
    ) -> DensePolynomial<F>
    {
        self.rcm.iter().zip(alpha[1..4].iter()).map(|(r, a)| r.scale(*a)).
            fold(self.psm.scale(Self::psdn_scalars(evals, params, alpha)[0]), |x, y| &x + &y)
    }
}
