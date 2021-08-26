/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use crate::gates::poseidon::*;
use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use crate::wires::COLUMNS;
use algebra::{FftField, SquareRootField};
use array_init::array_init;
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::{
    poseidon::{sbox, ArithmeticSpongeParams, Plonk15SpongeConstants, PlonkSpongeConstants},
    utils::{EvalUtils, PolyUtils},
};

//
// Stuff
//

enum CurrOrNext {
    Curr,
    Next,
}

/// An equation of the form `(curr | next)[i] = round(curr[j])`
struct RoundEquation {
    source: usize,
    target: (CurrOrNext, usize),
}

const ROUND_EQUATIONS: [RoundEquation; ROUNDS_PER_ROW] = [
    RoundEquation {
        source: 0,
        target: (CurrOrNext::Curr, 1),
    },
    RoundEquation {
        source: 1,
        target: (CurrOrNext::Curr, 2),
    },
    RoundEquation {
        source: 2,
        target: (CurrOrNext::Curr, 3),
    },
    RoundEquation {
        source: 3,
        target: (CurrOrNext::Curr, 4),
    },
    RoundEquation {
        source: 4,
        target: (CurrOrNext::Next, 0),
    },
];

//
// Implementations
//

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// poseidon quotient poly contribution computation `f^7 + c(x) - f(wx)`
    /// optimization: shuffle the intra-row rounds so that the final state is in one of the permutation columns
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
        // if this gate is not used, return zero polynomials
        if self.psm.is_zero() {
            return (
                self.zero4.clone(),
                self.zero8.clone(),
                DensePolynomial::<F>::zero(),
            );
        }

        // Conjunction of:
        // curr[round_range(1)] = round(curr[round_range(0)])
        // curr[round_range(2)] = round(curr[round_range(1)])
        // curr[round_range(3)] = round(curr[round_range(2)])
        // curr[round_range(4)] = round(curr[round_range(3)])
        // next[round_range(0)] = round(curr[round_range(4)])
        //
        // which expands e.g., to
        // curr[round_range(1)][0] =
        //      mds[0][0] * curr[round_range(0)][0]
        //    + mds[0][1] * curr[round_range(0)][1]
        //    + mds[0][2] * curr[round_range(0)][2]
        //    + rcm[round_range(1)][0]
        // curr[round_range(1)][1] =
        //      mds[1][0] * curr[round_range(0)][0]
        //    + mds[1][1] * curr[round_range(0)][1]
        //    + mds[1][2] * curr[round_range(0)][2]
        //    + rcm[round_range(1)][1]
        // ....

        // The rth position in this array contains the alphas used for the equations that
        // constrain the values of the (r+1)th state.

        /*
        let alp : [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|r| {
            let range = round_range(r);
            array_init(|i| alpha[range][i])
        }); */
        // let alp : [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|r| array_init(|i| alpha[r * SPONGE_WIDTH + i]));

        // In the logical order
        let sboxed: [[Evaluations<F, D<F>>; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|round| {
            let state = &polys.d8.this.w[round_to_cols(round)];
            let mut x: [_; SPONGE_WIDTH] = array_init(|i| state[i].clone());
            x.iter_mut().for_each(|p| {
                // TODO(mimoo): define a pow function on Evaluations
                p.evals
                    .iter_mut()
                    .for_each(|p| *p = sbox::<F, PlonkSpongeConstants>(*p))
            });
            x
        });

        /*
        let sboxed: [Evaluations<F, D<F>>; COLUMNS] = array_init(|i| {
            let mut x = array_init(|i| polys.d8.this.w[i].clone());
            x.iter_mut().for_each(|p| p.evals.iter_mut().for_each(|p| *p = sbox::<F, PlonkSpongeConstants>(*p)));
            x
        });

        let sboxed_scalars : [F; COLUMNS] = array_init(|i| {
            // find out what round i corresponds to, then look at
            round_range
        }); */

        // Each round equation has SPONGE_WIDTH many equations within it.
        // This ordering of alphas is somewhat arbitrary and maybe should be
        // changed depending on circuit efficiency.
        let alp: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|round| array_init(|i| alpha[round * SPONGE_WIDTH + i]));

        let lhs = ROUND_EQUATIONS.iter().fold(self.zero4.clone(), |acc, eq| {
            let (target_row, target_round) = &eq.target;
            let cols = match target_row {
                CurrOrNext::Curr => &polys.d4.this.w,
                CurrOrNext::Next => &polys.d4.next.w,
            };
            cols[round_to_cols(*target_round)]
                .iter()
                .zip(alp[eq.source].iter())
                .map(|(p, a)| p.scale(-*a))
                .fold(acc, |x, y| &x + &y)
        });

        let mut rhs = self.zero8.clone();
        for eq in ROUND_EQUATIONS.iter() {
            for (i, p) in sboxed[eq.source].iter().enumerate() {
                // Each of these contributes to the right hand side of SPONGE_WIDTH cell equations
                let coeff = (0..SPONGE_WIDTH).fold(F::zero(), |acc, j| {
                    acc + alp[eq.source][j] * params.mds[j][i]
                });
                rhs += &p.scale(coeff);
            }
        }

        let rc = alp
            .iter()
            .enumerate()
            .fold(DensePolynomial::<F>::zero(), |acc0, (round, als)| {
                als.iter()
                    .enumerate()
                    .fold(acc0, |acc, (col, a)| &acc + &self.rcm[round][col].scale(*a))
            });

        (&self.ps4 * &lhs, &self.ps8 * &rhs, rc)
        /*
        (
            &self.ps4 * &polys.d4.next.w.iter().zip(alpha[0..COLUMNS].iter()).map(|(p, a)| p.scale(-*a)).
                fold(self.zero4.clone(), |x, y| &x + &y),
            &self.ps8 * &lro.iter().zip(scalers.iter()).map(|(p, s)| p.scale(*s)).
                fold(self.zero8.clone(), |x, y| &x + &y),
            self.rcm.iter().zip(alpha[0..COLUMNS].iter()).map(|(p, a)| p.scale(*a)).
                fold(DensePolynomial::<F>::zero(), |x, y| &x + &y),
        )
        */
    }

    pub fn psdn_scalars(
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> Vec<F> {
        let w_zeta = evals[0].w;
        let sboxed: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|round| {
            array_init(|i| {
                let col = round_to_cols(round);
                sbox::<F, Plonk15SpongeConstants>(w_zeta[col][i])
            })
        });
        let alp: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|round| array_init(|i| alpha[round * SPONGE_WIDTH + i]));

        let lhs = ROUND_EQUATIONS.iter().fold(F::zero(), |acc, eq| {
            let (target_row, target_round) = &eq.target;
            let this_or_next = match target_row {
                CurrOrNext::Curr => 0,
                CurrOrNext::Next => 1,
            };
            evals[this_or_next].w[round_to_cols(*target_round)]
                .iter()
                .zip(alp[eq.source].iter())
                .map(|(p, a)| -*a * p)
                .fold(acc, |x, y| x + &y)
        });

        let mut rhs = F::zero();
        for eq in ROUND_EQUATIONS.iter() {
            let ss = sboxed[eq.source];
            let aa = alp[eq.source];
            for (i, p) in ss.iter().enumerate() {
                // Each of these contributes to the right hand side of SPONGE_WIDTH cell equations
                let coeff =
                    (0..SPONGE_WIDTH).fold(F::zero(), |acc, j| acc + aa[j] * params.mds[j][i]);
                rhs += coeff * p;
            }
        }

        // TODO(mimoo): how is that useful? we already have access to these
        let mut res = vec![lhs - rhs];
        for i in 0..COLUMNS {
            res.push(alpha[i]);
        }
        res
    }

    /// poseidon linearization poly contribution computation f^7 + c(x) - f(wx)
    pub fn psdn_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        let scalars = Self::psdn_scalars(evals, params, alpha)[0];
        self.rcm
            .iter()
            .flatten()
            .zip(alpha[0..COLUMNS].iter())
            .map(|(r, a)| r.scale(*a))
            .fold(self.psm.scale(scalars), |x, y| &x + &y)
    }
}

// TODO(mimoo): test to ensure equivalence between quotient and lnrz
