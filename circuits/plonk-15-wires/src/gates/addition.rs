/*****************************************************************************************************************

This source file implements non-special point (with distinct abscissas) Weierstrass curve addition

    ADD gate constrains

        (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
        (x2 - x1) * r = 1

    The constrains above are derived from the following EC Affine arithmetic equations:

        (x2 - x1) * s = y2 - y1
        s * s = x1 + x2 + x3
        (x1 - x3) * s = y3 + y1

        =>

        (x2 - x1) * (y3 + y1) = (y2 - y1) * (x1 - x3)
        (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) = (y3 + y1) * (y3 + y1)

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use algebra::FftField;
use array_init::array_init;

impl<F: FftField> CircuitGate<F> {
    pub fn create_add(row: usize, wires: GateWires) -> Self {
        CircuitGate {
            row,
            typ: GateType::Add,
            wires,
            c: vec![],
        }
    }

    pub fn verify_add(&self, witness: &[Vec<F>; COLUMNS]) -> bool {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        self.typ == GateType::Add
            && [
                (this[2] - &this[0]) * &(this[5] + &this[1])
                    - (this[1] - &this[3]) * &(this[0] - &this[4]),
                (this[0] + &this[2] + &this[4]) * &(this[0] - &this[4]).square()
                    - (this[5] + &this[1]).square(),
                (this[2] - &this[0]) * &this[6] - F::one(),
            ]
            .iter()
            .all(|p| *p == F::zero())
    }

    pub fn add(&self) -> F {
        if self.typ == GateType::Add {
            F::one()
        } else {
            F::zero()
        }
    }
}
