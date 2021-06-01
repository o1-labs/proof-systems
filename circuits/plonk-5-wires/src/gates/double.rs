/*****************************************************************************************************************

This source file implements constraints for non-special point doubling on Weierstrass curve

DOUBLE gate constraints

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 - y1) = (3 * x1^2) * (x2 – x1)
    y1 * r = 1

Permutation constraints

    -> x1
    -> y1
    x2 ->
    y2 ->

The constraints above are derived from the following EC Affine arithmetic equations:

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    y2 = -y1 - s * (x2 – x1)

    =>

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)

    =>

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)

*****************************************************************************************************************/

use ark_ff::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_double(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::Double,
            wires,
            c: vec![]
        }
    }

    pub fn verify_double(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        self.typ == GateType::Double
        &&
        F::from(4 as u64) * &this[1].square() * &(this[2] + &this[0].double())
        ==
        F::from(9 as u64) * &this[0].square().square()
        &&
        this[1].double() * &(this[3] + &this[1])
        ==
        F::from(3 as u64) * &this[0].square() * &(this[0] - &this[2])
        &&
        this[1] * &this[4] == F::one()
    }

    pub fn double(&self) -> F {if self.typ == GateType::Double {F::one()} else {F::zero()}}
}
