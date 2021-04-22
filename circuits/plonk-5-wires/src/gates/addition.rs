/*****************************************************************************************************************

This source file implements non-special point (with distinct abscissas) Weierstrass curve addition

    ADD gate constraints
        (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
        (x2 - x1) * r = 1

    Permutation constraints
    
        -> x1
        -> y1
        -> x2
        -> y2
        x3 ->
        y3 ->

    The constraints above are derived from the following EC Affine arithmetic equations:

        (x2 - x1) * s = y2 - y1
        s * s = x1 + x2 + x3
        (x1 - x3) * s = y3 + y1

        =>

        (x2 - x1) * (y3 + y1) = (y2 - y1) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) = (y3 + y1) * (y3 + y1)

*****************************************************************************************************************/

use algebra::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_add(row: usize, wires: &[GateWires; 2]) -> Vec<Self>
    {
        vec![
            CircuitGate
            {
                row,
                typ: GateType::Add,
                wires: wires[0],
                c: vec![]
            },
            CircuitGate
            {
                row: row + 1,
                typ: GateType::Zero,
                wires: wires[1],
                c: vec![]
            },
        ]
    }

    pub fn verify_add(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][self.row+1]);

        self.typ == GateType::Add
        &&
        (this[2] - &this[0]) * &(next[1] + &this[1])
        ==
        (this[3] - &this[1]) * &(this[0] - &next[0])
        &&
        (this[0] + &this[2] + &next[0]) *
            &(this[0] - &next[0]).square()
        ==
        (next[1] + &this[1]).square()
        &&
        (this[2] - &this[0]) * &this[4] == F::one()
    }

    pub fn add(&self) -> F {if self.typ == GateType::Add {F::one()} else {F::zero()}}
}
