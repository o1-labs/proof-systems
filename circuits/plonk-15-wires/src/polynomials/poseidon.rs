/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use crate::gates::poseidon::*;
use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use crate::wires::COLUMNS;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use array_init::array_init;
use oracle::{
    poseidon::{sbox, ArithmeticSpongeParams, Plonk15SpongeConstants},
    utils::{EvalUtils, PolyUtils},
};

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    // poseidon quotient poly contribution computation f^7 + c(x) - f(wx)
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
        // TODO: fix this code
        unimplemented!();
        /*
        if self.psm.is_zero() {
            return (
                self.zero4.clone(),
                self.zero8.clone(),
                DensePolynomial::<F>::zero(),
            );
        }

        // segregate into prtmutation section
        let mut alp: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|j| array_init(|i| alpha[j * ROUNDS_PER_ROW + i]));
        let mut state: [[Evaluations<F, D<F>>; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|i| array_init(|j| polys.d8.this.w[i * ROUNDS_PER_ROW + j].clone()));

        // this is the current state
        let mut perm = state.clone();

        // permute the cuccent state
        perm.iter_mut().for_each(|p| {
            p.iter_mut()
                .for_each(|r| *r = sbox::<F, Plonk15SpongeConstants>(*r))
        });

        let p4: [Evaluations<F, D<F>>; ROUNDS_PER_ROW] = array_init(|i| {
            polys
                .d4
                .next
                .w
                .iter()
                .zip(alpha[i][0..COLUMNS].iter())
                .map(|(p, a)| p.scale(-*a))
                .fold(self.zero4.clone(), |x, y| &x + &y)
        });
        let p8: [Evaluations<F, D<F>>; ROUNDS_PER_ROW] = array_init(|i| {});

        (
            &self.ps4
                * &polys
                    .d4
                    .next
                    .w
                    .iter()
                    .zip(alpha[0..COLUMNS].iter())
                    .map(|(p, a)| p.scale(-*a))
                    .fold(self.zero4.clone(), |x, y| &x + &y),
            &self.ps8
                * &lro
                    .iter()
                    .zip(scalers.iter())
                    .map(|(p, s)| p.scale(*s))
                    .fold(self.zero8.clone(), |x, y| &x + &y),
            self.rcm
                .iter()
                .zip(alpha[0..COLUMNS].iter())
                .map(|(p, a)| p.scale(*a))
                .fold(DensePolynomial::<F>::zero(), |x, y| &x + &y),
        )
        */
    }

    pub fn psdn_scalars(
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> Vec<F> {
        let sbox = evals[0]
            .w
            .iter()
            .map(|&w| sbox::<F, Plonk15SpongeConstants>(w))
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

    // poseidon linearization poly contribution computation f^7 + c(x) - f(wx)
    pub fn psdn_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        DensePolynomial::<F>::zero()
    }
}
