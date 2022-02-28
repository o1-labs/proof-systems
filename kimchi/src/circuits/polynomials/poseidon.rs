//! This module implements the Poseidon constraint polynomials.

use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::expr::{prologue::*, Cache, ConstantExpr};
use crate::circuits::gate::{CurrOrNext, GateType};
use crate::circuits::gates::poseidon::*;
use ark_ff::{FftField, Field};
use oracle::poseidon::{PlonkSpongeConstants15W, SpongeConstants};
use std::marker::PhantomData;
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

/// Implementation of the Poseidon gate
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
#[derive(Default)]
pub struct Poseidon<F>(PhantomData<F>);

impl<F> Poseidon<F> where F: Field {}

impl<F> Argument<F> for Poseidon<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Poseidon);
    const CONSTRAINTS: usize = 15;

    fn constraints() -> Vec<E<F>> {
        let mut res = vec![];
        let mut cache = Cache::default();

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
                .map(|i| cache.cache(witness_curr(i).pow(PlonkSpongeConstants15W::SPONGE_BOX)))
                .collect();

            res.extend(round_to_cols(target_round).enumerate().map(|(j, col)| {
                let rc = coeff(idx);

                idx += 1;
                witness(col, target_row)
                    - sboxed
                        .iter()
                        .zip(mds[j].iter())
                        .fold(rc, |acc, (x, c)| acc + E::Constant(c.clone()) * x.clone())
            }));
        }
        res
    }
}
