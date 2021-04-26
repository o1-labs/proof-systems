/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use crate::constraints::CSConstants;
use crate::polynomial::WitnessOverDomains;
use crate::scalars::ProofEvaluations;
use crate::wires::COLUMNS;
use algebra::{FftField, SquareRootField};
use array_init::array_init;
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::{
    poseidon::ArithmeticSpongeParams,
    poseidon_5_wires::{sbox, PlonkSpongeConstants},
    utils::{EvalUtils, PolyUtils},
};

pub trait CSPoseidonGate<F: FftField + SquareRootField>: CSConstants<F> {
    fn rcm(&self) -> &[DensePolynomial<F>; COLUMNS]; // round constant polynomials
    fn psm(&self) -> &DensePolynomial<F>; // poseidon constraint selector polynomial
    fn ps4(&self) -> &Evaluations<F, D<F>>; // selector over domain.d4
    fn ps8(&self) -> &Evaluations<F, D<F>>; // selector over domain.d8

    // poseidon quotient poly contribution computation f^5 + c(x) - f(wx)
    fn psdn_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> (
        Evaluations<F, D<F>>,
        Evaluations<F, D<F>>,
        DensePolynomial<F>,
    ) {
        if self.psm().is_zero() {
            return (
                self.zero4().clone(),
                self.zero8().clone(),
                DensePolynomial::<F>::zero(),
            );
        }

        let mut lro: [Evaluations<F, D<F>>; COLUMNS] = array_init(|i| polys.d8.this.w[i].clone());
        lro.iter_mut().for_each(|p| {
            p.evals
                .iter_mut()
                .for_each(|p| *p = sbox::<F, PlonkSpongeConstants>(*p))
        });

        let scalers = (0..COLUMNS)
            .map(|i| (0..COLUMNS).fold(F::zero(), |x, j| alpha[j] * params.mds[j][i] + x))
            .collect::<Vec<_>>();
        (
            self.ps4()
                * &polys
                    .d4
                    .next
                    .w
                    .iter()
                    .zip(alpha[0..COLUMNS].iter())
                    .map(|(p, a)| p.scale(-*a))
                    .fold(self.zero4().clone(), |x, y| &x + &y),
            self.ps8()
                * &lro
                    .iter()
                    .zip(scalers.iter())
                    .map(|(p, s)| p.scale(*s))
                    .fold(self.zero8().clone(), |x, y| &x + &y),
            self.rcm()
                .iter()
                .zip(alpha[0..COLUMNS].iter())
                .map(|(p, a)| p.scale(*a))
                .fold(DensePolynomial::<F>::zero(), |x, y| &x + &y),
        )
    }

    fn psdn_scalars(
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> Vec<F> {
        let sbox = evals[0]
            .w
            .iter()
            .map(|&w| sbox::<F, PlonkSpongeConstants>(w))
            .collect::<Vec<_>>();
        let lro = params
            .mds
            .iter()
            .map(|m| {
                sbox.iter()
                    .zip(m.iter())
                    .fold(F::zero(), |x, (s, &m)| m * s + x)
            })
            .collect::<Vec<_>>();

        vec![
            (0..lro.len()).fold(F::zero(), |x, i| x + alpha[i] * (lro[i] - evals[1].w[i])),
            alpha[0],
            alpha[1],
            alpha[2],
            alpha[3],
            alpha[4],
        ]
    }

    // poseidon linearization poly contribution computation f^5 + c(x) - f(wx)
    fn psdn_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        self.rcm()
            .iter()
            .zip(alpha[0..COLUMNS].iter())
            .map(|(r, a)| r.scale(*a))
            .fold(
                self.psm()
                    .scale(Self::psdn_scalars(evals, params, alpha)[0]),
                |x, y| &x + &y,
            )
    }
}
