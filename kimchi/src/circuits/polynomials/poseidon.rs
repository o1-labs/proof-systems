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

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::{constraints::ExprOps, Cache},
        gate::{CircuitGate, CurrOrNext, GateType},
        polynomial::COLUMNS,
        wires::{GateWires, Wire},
    },
    curve::KimchiCurve,
};
use ark_ff::{Field, PrimeField};
use mina_poseidon::{
    constants::{PlonkSpongeConstantsKimchi, SpongeConstants},
    poseidon::{sbox, ArithmeticSponge, ArithmeticSpongeParams, Sponge},
};
use std::{marker::PhantomData, ops::Range};
use CurrOrNext::{Curr, Next};

//
// Constants
//

/// Width of the sponge
pub const SPONGE_WIDTH: usize = PlonkSpongeConstantsKimchi::SPONGE_WIDTH;

/// Number of rows
pub const ROUNDS_PER_ROW: usize = COLUMNS / SPONGE_WIDTH;

/// Number of rounds
pub const ROUNDS_PER_HASH: usize = PlonkSpongeConstantsKimchi::PERM_ROUNDS_FULL;

/// Number of PLONK rows required to implement Poseidon
pub const POS_ROWS_PER_HASH: usize = ROUNDS_PER_HASH / ROUNDS_PER_ROW;

/// The order in a row in which we store states before and after permutations
pub const STATE_ORDER: [usize; ROUNDS_PER_ROW] = [
    0, // the first state is stored first
    // we skip the next column for subsequent states
    2, 3, 4,
    // we store the last state directly after the first state,
    // so that it can be used in the permutation argument
    1,
];

/// Given a Poseidon round from 0 to 4 (inclusive),
/// returns the columns (as a range) that are used in this round.
pub const fn round_to_cols(i: usize) -> Range<usize> {
    let slot = STATE_ORDER[i];
    let start = slot * SPONGE_WIDTH;
    start..(start + SPONGE_WIDTH)
}

impl<F: PrimeField> CircuitGate<F> {
    pub fn create_poseidon(
        wires: GateWires,
        // Coefficients are passed in in the logical order
        coeffs: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW],
    ) -> Self {
        let coeffs = coeffs.iter().flatten().copied().collect();
        CircuitGate::new(GateType::Poseidon, wires, coeffs)
    }

    /// `create_poseidon_gadget(row, first_and_last_row, round_constants)`  creates an entire set of constraint for a Poseidon hash.
    /// For that, you need to pass:
    /// - the index of the first `row`
    /// - the first and last rows' wires (because they are used in the permutation)
    /// - the round constants
    /// The function returns a set of gates, as well as the next pointer to the circuit (next empty absolute row)
    pub fn create_poseidon_gadget(
        // the absolute row in the circuit
        row: usize,
        // first and last row of the poseidon circuit (because they are used in the permutation)
        first_and_last_row: [GateWires; 2],
        round_constants: &[Vec<F>],
    ) -> (Vec<Self>, usize) {
        let mut gates = vec![];

        // create the gates
        let relative_rows = 0..POS_ROWS_PER_HASH;
        let last_row = row + POS_ROWS_PER_HASH;
        let absolute_rows = row..last_row;

        for (abs_row, rel_row) in absolute_rows.zip(relative_rows) {
            // the 15 wires for this row
            let wires = if rel_row == 0 {
                first_and_last_row[0]
            } else {
                std::array::from_fn(|col| Wire { col, row: abs_row })
            };

            // round constant for this row
            let coeffs = std::array::from_fn(|offset| {
                let round = rel_row * ROUNDS_PER_ROW + offset;
                std::array::from_fn(|field_el| round_constants[round][field_el])
            });

            // create poseidon gate for this row
            gates.push(CircuitGate::create_poseidon(wires, coeffs));
        }

        // final (zero) gate that contains the output of poseidon
        gates.push(CircuitGate::zero(first_and_last_row[1]));

        //
        (gates, last_row)
    }

    /// Checks if a witness verifies a poseidon gate
    ///
    /// # Errors
    ///
    /// Will give error if `self.typ` is not `Poseidon` gate, or `state` does not match after `permutation`.
    pub fn verify_poseidon<G: KimchiCurve<ScalarField = F>>(
        &self,
        row: usize,
        // TODO(mimoo): we should just pass two rows instead of the whole witness
        witness: &[Vec<F>; COLUMNS],
    ) -> Result<(), String> {
        ensure_eq!(
            self.typ,
            GateType::Poseidon,
            "incorrect gate type (should be poseidon)"
        );

        // fetch each state in the right order
        let mut states = vec![];
        for round in 0..ROUNDS_PER_ROW {
            let cols = round_to_cols(round);
            let state: Vec<F> = witness[cols].iter().map(|col| col[row]).collect();
            states.push(state);
        }
        // (last state is in next row)
        let cols = round_to_cols(0);
        let next_row = row + 1;
        let last_state: Vec<F> = witness[cols].iter().map(|col| col[next_row]).collect();
        states.push(last_state);

        // round constants
        let rc = self.rc();
        let mds = &G::sponge_params().mds;

        // for each round, check that the permutation was applied correctly
        for round in 0..ROUNDS_PER_ROW {
            for (i, mds_row) in mds.iter().enumerate() {
                // i-th(new_state) = i-th(rc) + mds(sbox(state))
                let state = &states[round];
                let mut new_state = rc[round][i];
                for (&s, mds) in state.iter().zip(mds_row.iter()) {
                    let sboxed = sbox::<F, PlonkSpongeConstantsKimchi>(s);
                    new_state += sboxed * mds;
                }

                ensure_eq!(
                    new_state,
                    states[round + 1][i],
                    format!(
                        "poseidon: permutation of state[{}] -> state[{}][{}] is incorrect",
                        round,
                        round + 1,
                        i
                    )
                );
            }
        }

        Ok(())
    }

    pub fn ps(&self) -> F {
        if self.typ == GateType::Poseidon {
            F::one()
        } else {
            F::zero()
        }
    }

    /// round constant that are relevant for this specific gate
    pub fn rc(&self) -> [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] {
        std::array::from_fn(|round| {
            std::array::from_fn(|col| {
                if self.typ == GateType::Poseidon {
                    self.coeffs[SPONGE_WIDTH * round + col]
                } else {
                    F::zero()
                }
            })
        })
    }
}

/// `generate_witness(row, params, witness_cols, input)` uses a sponge initialized with
/// `params` to generate a witness for starting at row `row` in `witness_cols`,
/// and with input `input`.
///
/// # Panics
///
/// Will panic if the `circuit` has `INITIAL_ARK`.
#[allow(clippy::assertions_on_constants)]
pub fn generate_witness<F: Field>(
    row: usize,
    params: &'static ArithmeticSpongeParams<F>,
    witness_cols: &mut [Vec<F>; COLUMNS],
    input: [F; SPONGE_WIDTH],
) {
    // add the input into the witness
    witness_cols[0][row] = input[0];
    witness_cols[1][row] = input[1];
    witness_cols[2][row] = input[2];

    // set the sponge state
    let mut sponge = ArithmeticSponge::<F, PlonkSpongeConstantsKimchi>::new(params);
    sponge.state = input.into();

    // for the poseidon rows
    for row_idx in 0..POS_ROWS_PER_HASH {
        let row = row + row_idx;
        for round in 0..ROUNDS_PER_ROW {
            // the last round makes use of the next row
            let maybe_next_row = if round == ROUNDS_PER_ROW - 1 {
                row + 1
            } else {
                row
            };

            //
            let abs_round = round + row_idx * ROUNDS_PER_ROW;

            // apply the sponge and record the result in the witness
            assert!(
                !PlonkSpongeConstantsKimchi::PERM_INITIAL_ARK,
                "this won't work if the circuit has an INITIAL_ARK"
            );
            sponge.full_round(abs_round);

            // apply the sponge and record the result in the witness
            let cols_to_update = round_to_cols((round + 1) % ROUNDS_PER_ROW);
            witness_cols[cols_to_update]
                .iter_mut()
                .zip(sponge.state.iter())
                // update the state (last update is on the next row)
                .for_each(|(w, s)| w[maybe_next_row] = *s);
        }
    }
}

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
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Poseidon);
    const CONSTRAINTS: u32 = 15;

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>, cache: &mut Cache) -> Vec<T> {
        let mut res = vec![];

        let mut idx = 0;

        //~ We define $M_{r, c}$ as the MDS matrix at row $r$ and column $c$.
        let mds: Vec<Vec<_>> = (0..SPONGE_WIDTH)
            .map(|row| (0..SPONGE_WIDTH).map(|col| env.mds(row, col)).collect())
            .collect();

        for e in &ROUND_EQUATIONS {
            let &RoundEquation {
                source,
                target: (target_row, target_round),
            } = e;
            //~
            //~ We define the S-box operation as $w^S$ for $S$ the `SPONGE_BOX` constant.
            let sboxed: Vec<_> = round_to_cols(source)
                .map(|i| {
                    cache.cache(
                        env.witness_curr(i)
                            .pow(u64::from(PlonkSpongeConstantsKimchi::PERM_SBOX)),
                    )
                })
                .collect();

            for (j, col) in round_to_cols(target_round).enumerate() {
                //~
                //~ We store the 15 round constants $r_i$ required for the 5 rounds (3 per round) in the coefficient table:
                //~
                //~ |  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
                //~ |:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
                //~ | r0 | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | r11 | r12 | r13 | r14 |
                let rc = env.coeff(idx);

                idx += 1;

                //~
                //~ The initial state, stored in the first three registers, are not constrained.
                //~ The following 4 states (of 3 field elements), including 1 in the next row,
                //~ are constrained to represent the 5 rounds of permutation.
                //~ Each of the associated 15 registers is associated to a constraint, calculated as:
                //~
                //~ first round:
                //~
                //~ * $w_6 - \left(r_0 + (M_{0, 0} w_0^S + M_{0, 1} w_1^S + M_{0, 2} w_2^S)\right)$
                //~ * $w_7 - \left(r_1 + (M_{1, 0} w_0^S + M_{1, 1} w_1^S + M_{1, 2} w_2^S)\right)$
                //~ * $w_8 - \left(r_2 + (M_{2, 0} w_0^S + M_{2, 1} w_1^S + M_{2, 2} w_2^S)\right)$
                //~
                //~ second round:
                //~
                //~ * $w_9 - \left(r_3 + (M_{0, 0} w_6^S + M_{0, 1} w_7^S + M_{0, 2} w_8^S)\right)$
                //~ * $w_{10} - \left(r_4 + (M_{1, 0} w_6^S + M_{1, 1} w_7^S + M_{1, 2} w_8^S)\right)$
                //~ * $w_{11} - \left(r_5 + (M_{2, 0} w_6^S + M_{2, 1} w_7^S + M_{2, 2} w_8^S)\right)$
                //~
                //~ third round:
                //~
                //~ * $w_{12} - \left(r_6 + (M_{0, 0} w_9^S + M_{0, 1} w_{10}^S + M_{0, 2} w_{11}^S)\right)$
                //~ * $w_{13} - \left(r_7 + (M_{1, 0} w_9^S + M_{1, 1} w_{10}^S + M_{1, 2} w_{11}^S)\right)$
                //~ * $w_{14} - \left(r_8 + (M_{2, 0} w_9^S + M_{2, 1} w_{10}^S + M_{2, 2} w_{11}^S)\right)$
                //~
                //~ fourth round:
                //~
                //~ * $w_3 - \left(r_9 + (M_{0, 0} w_{12}^S + M_{0, 1} w_{13}^S + M_{0, 2} w_{14}^S)\right)$
                //~ * $w_4 - \left(r_{10} + (M_{1, 0} w_{12}^S + M_{1, 1} w_{13}^S + M_{1, 2} w_{14}^S)\right)$
                //~ * $w_5 - \left(r_{11} + (M_{2, 0} w_{12}^S + M_{2, 1} w_{13}^S + M_{2, 2} w_{14}^S)\right)$
                //~
                //~ fifth round:
                //~
                //~ * $w_{0, next} - \left(r_{12} + (M_{0, 0} w_3^S + M_{0, 1} w_4^S + M_{0, 2} w_5^S)\right)$
                //~ * $w_{1, next} - \left(r_{13} + (M_{1, 0} w_3^S + M_{1, 1} w_4^S + M_{1, 2} w_5^S)\right)$
                //~ * $w_{2, next} - \left(r_{14} + (M_{2, 0} w_3^S + M_{2, 1} w_4^S + M_{2, 2} w_5^S)\right)$
                //~
                //~ where $w_{i, next}$ is the polynomial $w_i(\omega x)$ which points to the next row.
                let constraint = env.witness(target_row, col)
                    - sboxed
                        .iter()
                        .zip(mds[j].iter())
                        .fold(rc, |acc, (x, c)| acc + c.clone() * x.clone());
                res.push(constraint);
            }
        }
        res
    }
}
