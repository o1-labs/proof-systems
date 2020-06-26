/*****************************************************************************************************************

This source file implements Posedon constraint gate Plonk primitive.

Constraint vector format:

    [rc; SPONGE_WIDTH]: round constants
    fp:                 full/partial round indicator selector

*****************************************************************************************************************/

use algebra::Field;
use oracle::poseidon::sbox;
use crate::gate::{CircuitGate, GateType, SPONGE_WIDTH};

impl<F: Field> CircuitGate<F>
{
    pub fn create_poseidon
    (
        l: (usize, usize),
        r: (usize, usize),
        o: (usize, usize),
        rc: [F; SPONGE_WIDTH],
        fp: F,
    ) -> Self
    {
        CircuitGate
        {
            typ: GateType::Poseidon,
            l,
            r,
            o,
            c: vec![rc[0], rc[1], rc[2], fp]
        }
    }

    pub fn verify_poseidon(&self, witness: &Vec<F>, next: &Self) -> bool
    {
        let fp = self.fp();
        let pf = F::one() - &fp;

        self.typ == GateType::Poseidon
        &&
        sbox(witness[self.l.0]) +
        &(fp * &sbox(witness[self.o.0])) + &(pf * &witness[self.o.0]) +
        &self.rc()[0] == witness[next.l.0]
        &&
        sbox(witness[self.l.0]) +
        &(fp * &sbox(witness[self.r.0])) + &(pf * &witness[self.r.0]) +
        &self.rc()[1] == witness[next.r.0]
        &&
        fp * &sbox(witness[self.r.0]) + &(pf * &witness[self.r.0]) +
        &(fp * &sbox(witness[self.o.0])) + &(pf * &witness[self.o.0]) +
        &self.rc()[2] == witness[next.o.0]
    }

    pub fn fp(&self) -> F {if self.typ == GateType::Poseidon {self.c[3]} else {F::zero()}}
    pub fn rc(&self) -> [F; 3] {if self.typ == GateType::Poseidon {[self.c[0], self.c[1], self.c[2]]} else {[F::zero(); 3]}}
}
