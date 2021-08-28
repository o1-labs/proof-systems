/*****************************************************************************************************************

This source file implements Posedon constraint gate Plonk primitive.

Constraint vector format:

    [rc; SPONGE_WIDTH]: round constants

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::Wire;
use crate::{nolookup::constraints::ConstraintSystem, wires::GateWires, wires::COLUMNS};
use algebra::FftField;
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
        row: usize,
        wires: GateWires,
        // Coefficients are passed in in the logical order
        c: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW],
    ) -> Self {
        CircuitGate {
            row,
            typ: GateType::Poseidon,
            wires,
            c: c.iter().flatten().map(|x| *x).collect(),
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
        round_constants: &Vec<Vec<F>>,
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
                let round = rel_row * ROUNDS_PER_ROW + offset + 1;
                array_init(|field_el| round_constants[round][field_el])
            });

            // create poseidon gate for this row
            gates.push(CircuitGate::create_poseidon(abs_row, wires, coeffs));
        }

        // final (zero) gate that contains the output of poseidon
        gates.push(CircuitGate::zero(last_row, first_and_last_row[1]));

        //
        (gates, last_row)
    }

    pub fn verify_poseidon(&self, witness: &[Vec<F>; COLUMNS], cs: &ConstraintSystem<F>) -> bool {
        // TODO: Needs to be fixed

        let this: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|round| {
            let wire = STATE_ORDER[round];
            array_init(|col| witness[col + wire * SPONGE_WIDTH][self.row])
        });
        let next: [F; SPONGE_WIDTH] =
            array_init(|i| witness[i + STATE_ORDER[0] * SPONGE_WIDTH][self.row + 1]);

        let rc = self.rc();

        let perm: [Vec<F>; ROUNDS_PER_ROW] = array_init(|round| {
            cs.fr_sponge_params
                .mds
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    rc[round][i]
                        + &this[round]
                            .iter()
                            .zip(m.iter())
                            .fold(F::zero(), |x, (s, &m)| {
                                m * sbox::<F, PlonkSpongeConstants15W>(*s) + x
                            })
                })
                .collect::<Vec<_>>()
        });

        self.typ == GateType::Poseidon
            && perm.iter().zip(this.iter().skip(1)).all(|(p, n)| p == n)
            && perm[ROUNDS_PER_ROW - 1] == next
    }

    pub fn ps(&self) -> F {
        if self.typ == GateType::Poseidon {
            F::one()
        } else {
            F::zero()
        }
    }

    // Coefficients are output here in the logical order
    pub fn rc(&self) -> [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] {
        array_init(|round| {
            array_init(|col| {
                if self.typ == GateType::Poseidon {
                    self.c[SPONGE_WIDTH * round + col]
                } else {
                    F::zero()
                }
            })
        })
    }
}
