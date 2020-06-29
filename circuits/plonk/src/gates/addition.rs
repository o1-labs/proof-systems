/*****************************************************************************************************************

This source file implements non-special point (with distinct abscissas) Weierstrass curve addition

    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1
 
    =>

    (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
    (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)

constraint gate Plonk primitive. The constraint consists of two consecutive gates:

1. First gate constrains the point addition
2. Second gate constrains the abscissas distinctness check

Constraint equations on wires l, r, o, l_next, r_next, o_next where
l=y1, r=y2, o=y3, l_next=x1, r_next=x2, o_next=x3:

    (r_next - l_next) * (o + l) - (l - r) * (l_next - o_next) = 0
    (l_next + r_next + o_next) * (l_next - o_next) * (l_next - o_next) - (o + l) * (o + l) = 0

*****************************************************************************************************************/

use algebra::Field;
use crate::gate::{CircuitGate, GateType};

impl<F: Field> CircuitGate<F>
{
    pub fn create_add
    (
        l1: (usize, usize),
        r1: (usize, usize),
        o1: (usize, usize),
        l2: (usize, usize),
        r2: (usize, usize),
        o2: (usize, usize),
    ) -> Vec<Self>
    {
        vec![
            CircuitGate
            {
                typ: GateType::Add1,
                l: l1,
                r: r1,
                o: o1,
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Add2,
                l: l2,
                r: r2,
                o: o2,
                c: vec![]
            },
        ]
    }

    pub fn verify_add1(&self, witness: &Vec<F>, next: &Self) -> bool
    {
        /*
            (r_next - l_next) * (o + l) - (l - r) * (l_next - o_next) = 0
            (l_next + r_next + o_next) * (l_next - o_next) * (l_next - o_next) - (o + l) * (o + l) = 0
        */
        self.typ == GateType::Add1
        &&
        (witness[next.r.0] - &witness[next.l.0]) * &(witness[self.o.0] + &witness[self.l.0]) ==
        (witness[self.r.0] - &witness[self.l.0]) * &(witness[next.l.0] - &witness[next.o.0])
        &&
        (witness[next.l.0] + &witness[next.r.0] + &witness[next.o.0]) *
            &(witness[next.l.0] - &witness[next.o.0]) *
            &(witness[next.l.0] - &witness[next.o.0]) ==
        (witness[self.o.0] + &witness[self.l.0]) * &(witness[self.o.0] + &witness[self.l.0])
    }

    pub fn verify_add2(&self, witness: &Vec<F>) -> bool
    {
        self.typ == GateType::Add2 && witness[self.l.0] != witness[self.o.0]
    }

    pub fn add1(&self) -> F {if self.typ == GateType::Add1 {F::one()} else {F::zero()}}
    pub fn add2(&self) -> F {if self.typ == GateType::Add2 {F::one()} else {F::zero()}}
}
