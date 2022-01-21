/*****************************************************************************************************************

This source file implements Posedon constraint gate Plonk primitive.

Constraint vector format:

    [rc; SPONGE_WIDTH]: round constants

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::Wire;
use crate::{nolookup::constraints::ConstraintSystem, wires::GateWires, wires::COLUMNS};
use ark_ff::FftField;
use array_init::array_init;
use oracle::poseidon::{sbox, PlonkSpongeConstants15W, SpongeConstants};
use std::ops::Range;

//
// Constants
//

/// Width of the sponge
pub const SPONGE_WIDTH: usize = PlonkSpongeConstants15W::SPONGE_WIDTH;

/// Number of rows
pub const ROUNDS_PER_ROW: usize = COLUMNS / SPONGE_WIDTH;

/// Number of rounds
pub const ROUNDS_PER_HASH: usize = PlonkSpongeConstants15W::ROUNDS_FULL;

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

impl<F: FftField> CircuitGate<F> {
    pub fn create_poseidon(
        wires: GateWires,
        // Coefficients are passed in in the logical order
        rc: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW],
    ) -> Self {
        CircuitGate {
            typ: GateType::Poseidon,
            wires,
            coeffs: rc.iter().flatten().copied().collect(),
        }
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
                array_init(|col| Wire { col, row: abs_row })
            };

            // round constant for this row
            let coeffs = array_init(|offset| {
                let round = rel_row * ROUNDS_PER_ROW + offset;
                array_init(|field_el| round_constants[round][field_el])
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
    pub fn verify_poseidon(
        &self,
        row: usize,
        // TODO(mimoo): we should just pass two rows instead of the whole witness
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
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

        // for each round, check that the permutation was applied correctly
        for round in 0..ROUNDS_PER_ROW {
            for (i, mds_row) in cs.fr_sponge_params.mds.iter().enumerate() {
                // i-th(new_state) = i-th(rc) + mds(sbox(state))
                let state = &states[round];
                let mut new_state = rc[round][i];
                for (&s, mds) in state.iter().zip(mds_row.iter()) {
                    let sboxed = sbox::<F, PlonkSpongeConstants15W>(s);
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
        array_init(|round| {
            array_init(|col| {
                if self.typ == GateType::Poseidon {
                    self.coeffs[SPONGE_WIDTH * round + col]
                } else {
                    F::zero()
                }
            })
        })
    }
}
