//! This module implements the Poseidon constraint polynomials.

use crate::circuits::expr::{Cache, Column, ConstantExpr, E};
use crate::circuits::gate::{CurrOrNext, GateType};
use crate::circuits::gates::poseidon::*;
use ark_ff::{FftField, SquareRootField};
use oracle::poseidon::{PlonkSpongeConstants15W, SpongeConstants};
use std::ops::RangeInclusive;
use CurrOrNext::*;

/// All the information needed to construct a round in the Poseidon custom gate.
pub struct RoundSpec {
    /// the columns that contain the input
    pub input_cols: RangeInclusive<usize>,
    /// the row that contain the output
    pub output_row: CurrOrNext,
    /// the columns that contain the output
    pub output_cols: RangeInclusive<usize>,
}

/// Specifies in which columns the input of a row is stored,
/// as well as which row and columns the output the permutation is stored.
/// A Poseidon gates performs 5 rounds, with the last 5 round outputing
/// its result on the next row. Each round acts on a state of 3 columns.
/// The layout is also shuffled, so that the 4th round of the gate is stored
/// right after the first round. This is to let the permutation access it,
/// in case the final output lands on this state, instead of the next row's.
pub const ROUND_EQUATIONS: [RoundSpec; ROUNDS_PER_ROW] = [
    RoundSpec {
        input_cols: 0..=2,
        output_row: Curr,
        output_cols: 6..=8,
    },
    RoundSpec {
        input_cols: 6..=8,
        output_row: Curr,
        output_cols: 9..=11,
    },
    RoundSpec {
        input_cols: 9..=11,
        output_row: Curr,
        output_cols: 12..=14,
    },
    RoundSpec {
        input_cols: 12..=14,
        output_row: Curr,
        output_cols: 3..=5,
    },
    RoundSpec {
        input_cols: 3..=5,
        output_row: Next,
        output_cols: 0..=2,
    },
];

/// Poseidon quotient poly contribution computation `f^7 + c(x) - f(wx)`
/// Conjunction of:
/// curr[round_range(1)] = round(curr[round_range(0)])
/// curr[round_range(2)] = round(curr[round_range(1)])
/// curr[round_range(3)] = round(curr[round_range(2)])
/// curr[round_range(4)] = round(curr[round_range(3)])
/// next[round_range(0)] = round(curr[round_range(4)])
///
/// which expands e.g., to
/// curr[round_range(1)][0] =
///      mds[0][0] * sbox(curr[round_range(0)][0])
///    + mds[0][1] * sbox(curr[round_range(0)][1])
///    + mds[0][2] * sbox(curr[round_range(0)][2])
///    + rcm[round_range(1)][0]
/// curr[round_range(1)][1] =
///      mds[1][0] * sbox(curr[round_range(0)][0])
///    + mds[1][1] * sbox(curr[round_range(0)][1])
///    + mds[1][2] * sbox(curr[round_range(0)][2])
///    + rcm[round_range(1)][1]
/// ...
/// The rth position in this array contains the alphas used for the equations that
/// constrain the values of the (r+1)th state.
pub fn constraint<F: FftField + SquareRootField>(alphas: impl Iterator<Item = usize>) -> E<F> {
    let mut res = vec![];
    let mut cache = Cache::default();

    let mds: Vec<Vec<_>> = (0..SPONGE_WIDTH)
        .map(|row| {
            (0..SPONGE_WIDTH)
                .map(|col| ConstantExpr::Mds { row, col })
                .collect()
        })
        .collect();

    for (round, eq) in ROUND_EQUATIONS.iter().enumerate() {
        // sbox
        let mut sboxed = vec![];
        for input_col in eq.input_cols.clone() {
            let res =
                E::cell(Column::Witness(input_col), Curr).pow(PlonkSpongeConstants15W::SPONGE_BOX);
            sboxed.push(cache.cache(res));
        }

        for (state_i, output_col) in eq.output_cols.clone().enumerate() {
            // round constant
            let mut output = E::cell(Column::Coefficient(round * 3 + state_i), Curr);
            // + MDS(sboxed)
            for (x, c) in sboxed.iter().zip(&mds[state_i]) {
                output += E::Constant(c.clone()) * x.clone();
            }
            // create the constraint
            let constraint = E::cell(Column::Witness(output_col), eq.output_row) - output;

            res.push(constraint);
        }
    }

    E::cell(Column::Index(GateType::Poseidon), Curr) * E::combine_constraints(alphas, res)
}
