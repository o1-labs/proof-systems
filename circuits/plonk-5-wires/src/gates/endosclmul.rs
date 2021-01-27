/*****************************************************************************************************************

This source file implements group endomorphism optimised
variable base scalar multiplication custom Plonk constraints.

The constraints are designed as per the discussuion in
https://github.com/o1-labs/marlin/issues/41

*****************************************************************************************************************/

use algebra::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::{wires::GateWires, constraints::ConstraintSystem};

impl<F: FftField> CircuitGate<F>
{
    pub fn create_endomul(wires: &[GateWires; 4]) -> Vec<Self>
    {
        vec![
            CircuitGate
            {
                typ: GateType::Endomul1,
                wires: wires[0],
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Endomul2,
                wires: wires[1],
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Endomul3,
                wires: wires[2],
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Endomul4,
                wires: wires[3],
                c: vec![]
            },
        ]
    }

    pub fn verify_endomul1(&self, next: &Self, witness: &Vec<F>, cs: &ConstraintSystem<F>) -> bool
    {
        self.typ == GateType::Endomul1
        &&
        // verify booleanity of the scalar bits
        witness[self.wires.l.0] == witness[self.wires.l.0].square()
        &&
        witness[next.wires.l.0] == witness[next.wires.l.0].square()
        &&
        // xQ = (1 + (endo - 1) * b2i1) * xT
        witness[next.wires.r.0] == (F::one() + &((cs.endo - &F::one()) * &witness[self.wires.l.0])) * &witness[self.wires.r.0]
    }

    pub fn verify_endomul2(&self, next: &Self, witness: &Vec<F>) -> bool
    {
        self.typ == GateType::Endomul2
        &&
        // (xP - xQ) × λ1 = yP - (yT * (2 * b2i - 1))
        (witness[next.wires.l.0] - &witness[self.wires.r.0]) * &witness[next.wires.r.0]
        ==
        witness[next.wires.o.0] - &(witness[self.wires.o.0] * &(witness[self.wires.l.0].double() - &F::one()))
    }

    pub fn verify_endomul3(&self, next: &Self, witness: &Vec<F>) -> bool
    {
        let xr = witness[self.wires.r.0].square() - &witness[self.wires.l.0] - &witness[next.wires.r.0];
        let t = witness[self.wires.l.0] - &xr;
        let u = witness[self.wires.o.0].double() - &(t * &witness[self.wires.r.0]);

        self.typ == GateType::Endomul3
        &&
        // u^2 = t^2 * (xR + xP + xS)
        u.square() == t.square() * &(xr + &witness[self.wires.l.0] + &witness[next.wires.l.0])
        &&
        // (xP - xS) * u = t * (yS + yP)
        (witness[self.wires.l.0] - &witness[next.wires.l.0]) * &u == t * &(witness[self.wires.o.0] + &witness[next.wires.o.0])
    }

    pub fn verify_endomul4(&self, _next: &Self, _witness: &Vec<F>) -> bool
    {
        self.typ == GateType::Endomul4
    }

    pub fn endomul1(&self) -> F {if self.typ == GateType::Endomul1 {F::one()} else {F::zero()}}
    pub fn endomul2(&self) -> F {if self.typ == GateType::Endomul2 {F::one()} else {F::zero()}}
    pub fn endomul3(&self) -> F {if self.typ == GateType::Endomul3 {F::one()} else {F::zero()}}
    pub fn endomul4(&self) -> F {if self.typ == GateType::Endomul4 {F::one()} else {F::zero()}}
}
