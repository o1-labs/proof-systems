/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use crate::expr::{Cache, Column, ConstantExpr, E};
use crate::gate::{CurrOrNext, GateType};
use crate::gates::poseidon::*;
use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::wires::COLUMNS;
use ark_ff::{FftField, SquareRootField};
use ark_poly::univariate::DensePolynomial;
use array_init::array_init;
use o1_utils::ExtendedDensePolynomial;
use oracle::poseidon::{sbox, ArithmeticSpongeParams, PlonkSpongeConstants15W, SpongeConstants};
use CurrOrNext::*;

/// An equation of the form `(curr | next)[i] = round(curr[j])`
pub struct RoundEquation {
    pub source: usize,
    pub target: (CurrOrNext, usize),
}

pub const ROUND_EQUATIONS: [RoundEquation; ROUNDS_PER_ROW] = [
    RoundEquation {
        source: 0,
        target: (Curr, 1),
    },
    RoundEquation {
        source: 1,
        target: (Curr, 2),
    },
    RoundEquation {
        source: 2,
        target: (Curr, 3),
    },
    RoundEquation {
        source: 3,
        target: (Curr, 4),
    },
    RoundEquation {
        source: 4,
        target: (Next, 0),
    },
];

/// poseidon quotient poly contribution computation `f^7 + c(x) - f(wx)`
// Conjunction of:
// curr[round_range(1)] = round(curr[round_range(0)])
// curr[round_range(2)] = round(curr[round_range(1)])
// curr[round_range(3)] = round(curr[round_range(2)])
// curr[round_range(4)] = round(curr[round_range(3)])
// next[round_range(0)] = round(curr[round_range(4)])
//
// which expands e.g., to
// curr[round_range(1)][0] =
//      mds[0][0] * sbox(curr[round_range(0)][0])
//    + mds[0][1] * sbox(curr[round_range(0)][1])
//    + mds[0][2] * sbox(curr[round_range(0)][2])
//    + rcm[round_range(1)][0]
// curr[round_range(1)][1] =
//      mds[1][0] * sbox(curr[round_range(0)][0])
//    + mds[1][1] * sbox(curr[round_range(0)][1])
//    + mds[1][2] * sbox(curr[round_range(0)][2])
//    + rcm[round_range(1)][1]
// ...
// The rth position in this array contains the alphas used for the equations that
// constrain the values of the (r+1)th state.
pub fn constraint<F: FftField + SquareRootField>() -> E<F> {
    let mut res = vec![];
    let mut cache = Cache::new();

    let mut idx = 0;

    let mds: Vec<Vec<_>> = (0..SPONGE_WIDTH)
        .map(|row| {
            (0..SPONGE_WIDTH)
                .map(|col| ConstantExpr::Mds { row, col })
                .collect()
        })
        .collect();

    for e in ROUND_EQUATIONS.iter() {
        let &RoundEquation {
            source,
            target: (target_row, target_round),
        } = e;
        let sboxed: Vec<_> = round_to_cols(source)
            .map(|i| {
                cache.cache(
                    E::cell(Column::Witness(i), Curr).pow(PlonkSpongeConstants15W::SPONGE_BOX),
                )
            })
            .collect();

        res.extend(round_to_cols(target_round).enumerate().map(|(j, col)| {
            let rc = E::cell(Column::Coefficient(idx), Curr);

            idx += 1;

            E::cell(Column::Witness(col), target_row)
                - sboxed
                    .iter()
                    .zip(mds[j].iter())
                    .fold(rc, |acc, (x, c)| acc + E::Constant(c.clone()) * x.clone())
        }));
    }
    E::cell(Column::Index(GateType::Poseidon), Curr) * E::combine_constraints(0, res)
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    pub fn psdn_scalars(
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> Vec<F> {
        let w_zeta = evals[0].w;
        let sboxed: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|round| {
            array_init(|i| {
                let col = round_to_cols(round);
                sbox::<F, PlonkSpongeConstants15W>(w_zeta[col][i])
            })
        });
        let alp: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|round| array_init(|i| alpha[round * SPONGE_WIDTH + i]));

        let lhs = ROUND_EQUATIONS.iter().fold(F::zero(), |acc, eq| {
            let (target_row, target_round) = &eq.target;
            let cols = match target_row {
                Curr => &evals[0].w,
                Next => &evals[1].w,
            };
            cols[round_to_cols(*target_round)]
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

        let mut res = vec![lhs + rhs];

        // TODO(mimoo): how is that useful? we already have access to these
        for i in 0..COLUMNS {
            res.push(evals[0].poseidon_selector * alpha[i]);
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
        let scalars = Self::psdn_scalars(evals, params, alpha);
        self.coefficientsm
            .iter()
            .zip(scalars[1..].iter())
            .map(|(r, a)| r.scale(*a))
            .fold(self.psm.scale(scalars[0]), |x, y| &x + &y)
    }
}
