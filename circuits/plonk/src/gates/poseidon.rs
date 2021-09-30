/*****************************************************************************************************************

This source file implements Posedon constraint gate Plonk primitive.

Constraint vector format:

    [rc; SPONGE_WIDTH]: round constants

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::{constraints::ConstraintSystem, wires::GateWires};
use algebra::FftField;
use oracle::poseidon::{sbox, PlonkSpongeConstants, SpongeConstants};

impl<F: FftField> CircuitGate<F> {
    pub fn create_poseidon(wires: GateWires, rc: [F; PlonkSpongeConstants::SPONGE_WIDTH]) -> Self {
        CircuitGate {
            typ: GateType::Poseidon,
            wires,
            c: vec![rc[0], rc[1], rc[2]],
        }
    }

    pub fn verify_poseidon(&self, next: &Self, witness: &Vec<F>, cs: &ConstraintSystem<F>) -> bool {
        let rc = self.rc();
        let sbox = [
            sbox::<F, PlonkSpongeConstants>(witness[self.wires.l.0]),
            sbox::<F, PlonkSpongeConstants>(witness[self.wires.r.0]),
            sbox::<F, PlonkSpongeConstants>(witness[self.wires.o.0]),
        ];
        let next = [
            witness[next.wires.l.0],
            witness[next.wires.r.0],
            witness[next.wires.o.0],
        ];

        let perm = cs
            .fr_sponge_params
            .mds
            .iter()
            .enumerate()
            .map(|(i, m)| {
                rc[i]
                    + &sbox
                        .iter()
                        .zip(m.iter())
                        .fold(F::zero(), |x, (s, &m)| m * s + x)
            })
            .collect::<Vec<_>>();

        self.typ == GateType::Poseidon && !perm.iter().zip(next.iter()).any(|(p, n)| p != n)
    }

    pub fn ps(&self) -> F {
        if self.typ == GateType::Poseidon {
            F::one()
        } else {
            F::zero()
        }
    }
    pub fn rc(&self) -> [F; 3] {
        if self.typ == GateType::Poseidon {
            [self.c[0], self.c[1], self.c[2]]
        } else {
            [F::zero(); 3]
        }
    }
}
