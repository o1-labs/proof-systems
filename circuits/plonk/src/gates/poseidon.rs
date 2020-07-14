/*****************************************************************************************************************

This source file implements Posedon constraint gate Plonk primitive.

Constraint vector format:

    [rc; SPONGE_WIDTH]: round constants
    fp:                 full/partial round indicator selector

*****************************************************************************************************************/

use algebra::FftField;
use oracle::poseidon::sbox;
use crate::gate::{CircuitGate, GateType, SPONGE_WIDTH};
use crate::wires::GateWires;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_poseidon
    (
        wires: GateWires,
        rc: [F; SPONGE_WIDTH],
        fp: F,
    ) -> Self
    {
        CircuitGate
        {
            typ: GateType::Poseidon,
            wires,
            c: vec![rc[0], rc[1], rc[2], fp]
        }
    }

    pub fn verify_poseidon(&self, next: &Self, witness: &Vec<F>) -> bool
    {
        let fp = self.fp();
        let pf = F::one() - &fp;

        self.typ == GateType::Poseidon
        &&
        sbox(witness[self.wires.l.0]) +
        &(fp * &sbox(witness[self.wires.o.0])) + &(pf * &witness[self.wires.o.0]) +
        &self.rc()[0] == witness[next.wires.l.0]
        &&
        sbox(witness[self.wires.l.0]) +
        &(fp * &sbox(witness[self.wires.r.0])) + &(pf * &witness[self.wires.r.0]) +
        &self.rc()[1] == witness[next.wires.r.0]
        &&
        fp * &sbox(witness[self.wires.r.0]) + &(pf * &witness[self.wires.r.0]) +
        &(fp * &sbox(witness[self.wires.o.0])) + &(pf * &witness[self.wires.o.0]) +
        &self.rc()[2] == witness[next.wires.o.0]
    }

    pub fn ps(&self) -> F {if self.typ == GateType::Poseidon {F::one()} else {F::zero()}}
    pub fn fp(&self) -> F {if self.typ == GateType::Poseidon {self.c[3]} else {F::zero()}}
    pub fn rc(&self) -> [F; 3] {if self.typ == GateType::Poseidon {[self.c[0], self.c[1], self.c[2]]} else {[F::zero(); 3]}}
}
