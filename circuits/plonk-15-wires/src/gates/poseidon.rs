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
use oracle::poseidon::{sbox, Plonk15SpongeConstants, SpongeConstants};
use std::ops::Range;

//
// Constants
//

/// Width of the sponge
pub const SPONGE_WIDTH: usize = Plonk15SpongeConstants::SPONGE_WIDTH;

/// Number of rows
pub const ROUNDS_PER_ROW: usize = COLUMNS / SPONGE_WIDTH;

/// Number of rounds
pub const ROUNDS_PER_HASH: usize = Plonk15SpongeConstants::ROUNDS_FULL;

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
                                m * sbox::<F, Plonk15SpongeConstants>(*s) + x
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
