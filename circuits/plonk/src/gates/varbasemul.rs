/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk constraints.

The constraints are designed with 3 gates per bit of scalar modelled as per the discussuion of
https://github.com/zcash/zcash/issues/4254

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

Gate 0
    b*b = b
    (xT - xP) × λ1 = (yT) × (2·b - 1) - yP

Gate 1
    λ1^2 = xP + xT + xR
    (xP - xR) × (λ1 + λ2) = 2*yP
    λ2^2 = xR + xP + xS
    (xP - xS) × λ2 = yS + yP
=>
    xR = λ1^2 - xT - xP
    (xP - xR) × λ2 = 2*yP - (xP - xR) × λ1
    λ2^2 = xR + xP + xS
    (xP - xS) × λ2 = yS + yP
=>
    (2*xP - λ1^2 + xT) × λ2 = 2*yP - (2*xP - λ1^2 + xT) × λ1
    λ2^2 = λ1^2 - xT + xS
    (xP - xS) × λ2 = yS + yP
=>
    (2*yP - (2*xP - λ1^2 + xT) × λ1)^2 = (λ1^2 - xT + xS) * (2*xP - λ1^2 + xT)^2
    (xP - xS) × (2*yP - (2*xP - λ1^2 + xT) × λ1) = (yS + yP) * (2*xP - λ1^2 + xT)


*****************************************************************************************************************/

use algebra::Field;
use crate::gate::{CircuitGate, GateType};

impl<F: Field> CircuitGate<F>
{
    pub fn create_vbmul
    (
        l1: (usize, usize),
        r1: (usize, usize),
        o1: (usize, usize),
        l2: (usize, usize),
        r2: (usize, usize),
        o2: (usize, usize),
        l3: (usize, usize),
        r3: (usize, usize),
        o3: (usize, usize),
    ) -> Vec<Self>
    {
        vec![
            CircuitGate
            {
                typ: GateType::Vbmul1,
                l: l1,
                r: r1,
                o: o1,
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Vbmul2,
                l: l2,
                r: r2,
                o: o2,
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Vbmul3,
                l: l3,
                r: r3,
                o: o3,
                c: vec![]
            },
        ]
    }

    pub fn verify_vbmul1(&self, witness: &Vec<F>, next: &Self) -> bool
    {
        self.typ == GateType::Vbmul1
        &&
        // verify booleanity of the scalar bit
        witness[self.r.0] == witness[self.r.0].square()
        &&
        // (xP - xT) × λ1 = yP - (yT × (2·b - 1))
        (witness[next.l.0] - &witness[self.l.0]) * &witness[next.r.0]
        ==
        witness[next.o.0] - &(witness[self.o.0] * &(witness[self.r.0].double() - &F::one()))
    }

    pub fn verify_vbmul2(&self, witness: &Vec<F>, next: &Self) -> bool
    {
        // 2*xP - λ1^2 + xT
        let tmp = witness[self.l.0].double() - &witness[self.r.0].square() + &witness[next.r.0];

        self.typ == GateType::Vbmul2
        &&
        // (2*yP - (2*xP - λ1^2 + xT) × λ1)^2 = (λ1^2 - xT + xS) * (2*xP - λ1^2 + xT)^2
        (witness[self.o.0].double() - (tmp * &witness[self.r.0])).square()
        ==
        (witness[self.r.0].square() - &witness[next.r.0] + &witness[next.l.0]) * &tmp.square()
        &&
        // (xP - xS) × (2*yP - (2*xP - λ1^2 + xT) × λ1) = (yS + yP) * (2*xP - λ1^2 + xT)
        (witness[self.l.0] - &witness[next.l.0]) * &(witness[self.o.0].double() - &(tmp * &witness[self.r.0]))
        ==
        (witness[next.r.0] + &witness[self.o.0]) * &tmp
    }

    pub fn verify_vbmul3(&self, _witness: &Vec<F>, _next: &Self) -> bool
    {
        self.typ == GateType::Vbmul3
    }

    pub fn vbmul1(&self) -> F {if self.typ == GateType::Vbmul1 {F::one()} else {F::zero()}}
    pub fn vbmul2(&self) -> F {if self.typ == GateType::Vbmul2 {F::one()} else {F::zero()}}
    pub fn vbmul3(&self) -> F {if self.typ == GateType::Vbmul3 {F::one()} else {F::zero()}}
}
