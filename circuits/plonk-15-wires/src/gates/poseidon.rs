/*****************************************************************************************************************

This source file implements Posedon constraint gate Plonk primitive.

Constraint vector format:

    [rc; SPONGE_WIDTH]: round constants

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::{
    nolookup::constraints::ConstraintSystem,
    wires::GateWires,
    wires::{COLUMNS, WIRES},
};
use ark_ff::FftField;
use array_init::array_init;
use oracle::poseidon::{sbox, Plonk15SpongeConstants, SpongeConstants};

pub const SPONGE_WIDTH: usize = Plonk15SpongeConstants::SPONGE_WIDTH;
pub const ROUNDS_PER_ROW: usize = COLUMNS / SPONGE_WIDTH;

impl<F: FftField> CircuitGate<F> {
    pub fn create_poseidon(row: usize, wires: GateWires, c: Vec<F>) -> Self {
        CircuitGate {
            row,
            typ: GateType::Poseidon,
            wires,
            c,
        }
    }

    pub fn verify_poseidon(&self, witness: &[Vec<F>; COLUMNS], cs: &ConstraintSystem<F>) -> bool {
        let this: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|i| array_init(|j| witness[ROUNDS_PER_ROW * i + j][self.row]));
        let next: [F; SPONGE_WIDTH] = array_init(|i| witness[i][self.row + 1]);
        let rc = self.rc();

        let perm: [Vec<F>; ROUNDS_PER_ROW] = array_init(|j| {
            cs.fr_sponge_params
                .mds
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    rc[j][i]
                        + &this[j].iter().zip(m.iter()).fold(F::zero(), |x, (s, &m)| {
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
    pub fn rc(&self) -> [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] {
        array_init(|i| {
            array_init(|j| {
                if self.typ == GateType::Poseidon {
                    self.c[WIRES[ROUNDS_PER_ROW * i + j]]
                } else {
                    F::zero()
                }
            })
        })
    }
}
