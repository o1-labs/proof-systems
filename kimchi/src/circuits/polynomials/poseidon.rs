//! This module implements the Poseidon constraint polynomials.

//~ The poseidon gate encodes 5 rounds of the poseidon permutation.
//~ A state is represents by 3 field elements. For example,
//~ the first state is represented by `(s0, s0, s0)`,
//~ and the next state, after permutation, is represented by `(s1, s1, s1)`.
//~
//~ Below is how we store each state in the register table:
//~
//~ |  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
//~ |:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
//~ | s0 | s0 | s0 | s4 | s4 | s4 | s1 | s1 | s1 | s2 | s2 | s2 | s3 | s3 | s3 |
//~ | s5 | s5 | s5 |    |    |    |    |    |    |    |    |    |    |    |    |
//~
//~ The last state is stored on the next row. This last state is either used:
//~
//~ * with another Poseidon gate on that next row, representing the next 5 rounds.
//~ * or with a Zero gate, and a permutation to use the output elsewhere in the circuit.
//~ * or with another gate expecting an input of 3 field elements in its first registers.
//~
//~ ```admonish
//~ As some of the poseidon hash variants might not use $5k$ rounds (for some $k$),
//~ the result of the 4-th round is stored directly after the initial state.
//~ This makes that state accessible to the permutation.
//~ ```
//~

use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::expr::{prologue::*, Cache, ConstantExpr};
use crate::circuits::gate::{CurrOrNext, GateType};
use crate::circuits::gates::poseidon::*;
use ark_ff::{FftField, Field};
use oracle::poseidon::{PlonkSpongeConstantsKimchi, SpongeConstants};
use std::marker::PhantomData;
use CurrOrNext::*;

/// An equation of the form `(curr | next)[i] = round(curr[j])`
struct RoundEquation {
    pub source: usize,
    pub target: (CurrOrNext, usize),
}

/// For each round, the tuple (row, round) its state permutes to
const ROUND_EQUATIONS: [RoundEquation; ROUNDS_PER_ROW] = [
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
///
/// ```ignore
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
/// ```
///
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
    const CONSTRAINTS: u32 = 15;

    fn constraints() -> Vec<E<F>> {
        let mut res = vec![];
        let mut cache = Cache::default();

        let mut idx = 0;

        //~ We define $M_{r, c}$ as the MDS matrix at row $r$ and column $c$.
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
            //~
            //~ We define the S-box operation as $w^S$ for $S$ the `SPONGE_BOX` constant.
            let sboxed: Vec<_> = round_to_cols(source)
                .map(|i| {
                    cache.cache(witness_curr(i).pow(PlonkSpongeConstantsKimchi::SPONGE_BOX as u64))
                })
                .collect();

            for (j, col) in round_to_cols(target_round).enumerate() {
                //~
                //~ We store the 15 round constants $r_i$ required for the 5 rounds (3 per round) in the coefficient table:
                //~
                //~ |  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
                //~ |:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
                //~ | r0 | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | r11 | r12 | r13 | r14 |
                let rc = coeff(idx);

                idx += 1;

                //~
                //~ The initial state, stored in the first three registers, are not constrained.
                //~ The following 4 states (of 3 field elements), including 1 in the next row,
                //~ are constrained to represent the 5 rounds of permutation.
                //~ Each of the associated 15 registers is associated to a constraint, calculated as:
                //~
                //~ first round:
                //~ * $w_6 - [r_0 + (M_{0, 0} w_0^S + M_{0, 1} w_1^S + M_{0, 2} w_2^S)]$
                //~ * $w_7 - [r_1 + (M_{1, 0} w_0^S + M_{1, 1} w_1^S + M_{1, 2} w_2^S)]$
                //~ * $w_8 - [r_2 + (M_{2, 0} w_0^S + M_{2, 1} w_1^S + M_{2, 2} w_2^S)]$
                //~
                //~ second round:
                //~ * $w_9 - [r_3 + (M_{0, 0} w_6^S + M_{0, 1} w_7^S + M_{0, 2} w_8^S)]$
                //~ * $w_{10} - [r_4 + (M_{1, 0} w_6^S + M_{1, 1} w_7^S + M_{1, 2} w_8^S)]$
                //~ * $w_{11} - [r_5 + (M_{2, 0} w_6^S + M_{2, 1} w_7^S + M_{2, 2} w_8^S)]$
                //~
                //~ third round:
                //~ * $w_{12} - [r_6 + (M_{0, 0} w_9^S + M_{0, 1} w_{10}^S + M_{0, 2} w_{11}^S)]$
                //~ * $w_{13} - [r_7 + (M_{1, 0} w_9^S + M_{1, 1} w_{10}^S + M_{1, 2} w_{11}^S)]$
                //~ * $w_{14} - [r_8 + (M_{2, 0} w_9^S + M_{2, 1} w_{10}^S + M_{2, 2} w_{11}^S)]$
                //~
                //~ fourth round:
                //~ * $w_3 - [r_9 + (M_{0, 0} w_{12}^S + M_{0, 1} w_{13}^S + M_{0, 2} w_{14}^S)]$
                //~ * $w_4 - [r_{10} + (M_{1, 0} w_{12}^S + M_{1, 1} w_{13}^S + M_{1, 2} w_{14}^S)]$
                //~ * $w_5 - [r_{11} + (M_{2, 0} w_{12}^S + M_{2, 1} w_{13}^S + M_{2, 2} w_{14}^S)]$
                //~
                //~ fifth round:
                //~ * $w_{0, next} - [r_{12} + (M_{0, 0} w_3^S + M_{0, 1} w_4^S + M_{0, 2} w_5^S)]$
                //~ * $w_{1, next} - [r_{13} + (M_{1, 0} w_3^S + M_{1, 1} w_4^S + M_{1, 2} w_5^S)]$
                //~ * $w_{2, next} - [r_{14} + (M_{2, 0} w_3^S + M_{2, 1} w_4^S + M_{2, 2} w_5^S)]$
                //~
                //~ where $w_{i, next}$ is the polynomial $w_i(\omega x)$ which points to the next row.
                let constraint = witness(col, target_row)
                    - sboxed
                        .iter()
                        .zip(mds[j].iter())
                        .fold(rc, |acc, (x, c)| acc + E::Constant(c.clone()) * x.clone());
                res.push(constraint);
            }
        }
        res
    }
}
