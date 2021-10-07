/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use crate::constraints::ConstraintSystem;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use oracle::poseidon::{sbox, ArithmeticSpongeParams, PlonkSpongeConstantsBasic};
use rayon::prelude::*;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // poseidon quotient poly contribution computation f^5 + c(x) - f(wx)
    pub fn psdn_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> (
        Evaluations<F, D<F>>,
        Evaluations<F, D<F>>,
        DensePolynomial<F>,
    ) {
        if self.psm.is_zero() {
            return (
                self.ps4.clone(),
                self.ps8.clone(),
                DensePolynomial::<F>::zero(),
            );
        }

        let mut lro = [
            polys.d8.this.l.clone(),
            polys.d8.this.r.clone(),
            polys.d8.this.o.clone(),
        ];
        lro.iter_mut().for_each(|p| {
            p.evals
                .par_iter_mut()
                .for_each(|p| *p = sbox::<F, PlonkSpongeConstantsBasic>(*p))
        });

        let scalers = (0..params.mds.len())
            .map(|i| {
                (0..params.mds[i].len()).fold(F::zero(), |x, j| alpha[j] * params.mds[j][i] + x)
            })
            .collect::<Vec<_>>();

        (
            &self.ps4
                * &(&(&polys.d4.next.l.scale(-alpha[0]) - &polys.d4.next.r.scale(alpha[1]))
                    - &polys.d4.next.o.scale(alpha[2])),
            &self.ps8
                * &(&(&lro[0].scale(scalers[0]) + &lro[1].scale(scalers[1]))
                    + &lro[2].scale(scalers[2])),
            &(&self.rcm[0].scale(alpha[0]) + &self.rcm[1].scale(alpha[1]))
                + &self.rcm[2].scale(alpha[2]),
        )
    }

    pub fn psdn_scalars(
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> Vec<F> {
        let lro = params
            .mds
            .iter()
            .map(|m| {
                [
                    sbox::<F, PlonkSpongeConstantsBasic>(evals[0].l),
                    sbox::<F, PlonkSpongeConstantsBasic>(evals[0].r),
                    sbox::<F, PlonkSpongeConstantsBasic>(evals[0].o),
                ]
                .iter()
                .zip(m.iter())
                .fold(F::zero(), |x, (s, &m)| m * s + x)
            })
            .collect::<Vec<_>>();

        vec![
            (0..lro.len()).fold(F::zero(), |x, i| {
                x + alpha[i] * (lro[i] - [evals[1].l, evals[1].r, evals[1].o][i])
            }),
            alpha[0],
            alpha[1],
            alpha[2],
        ]
    }

    // poseidon linearization poly contribution computation f^5 + c(x) - f(wx)
    pub fn psdn_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        self.rcm
            .iter()
            .zip(alpha[0..3].iter())
            .map(|(r, a)| r.scale(*a))
            .fold(
                self.psm.scale(Self::psdn_scalars(evals, params, alpha)[0]),
                |x, y| &x + &y,
            )
    }
}
