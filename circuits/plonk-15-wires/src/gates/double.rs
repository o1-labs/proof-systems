/*****************************************************************************************************************

This source file implements constraints for non-special point doubling and tripling on Weierstrass curve

DOUBLE gate constraints
•	4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
•	2 * y1 * (y2 + y1) = (3 * x1^2) * (x1 – x2)
•	y1 * r1 = 1
•	
•	(x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
•	(x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)
•	(x2 - x1) * r2 = 1

The constraints above are derived from the following EC Affine arithmetic equations:

Doubling

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    y2 = y1 + s * (x2 – x1)

    =>

    2 * s * y1 = 3 * x1^2
    x2 = s^2 – 2*x1
    2 * y1 * (y2 - y1) = 3 * x1^2 * (x2 – x1)

    =>

    4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
    2 * y1 * (y2 + y1) = 3 * x1^2 * (x1 – x2)

Addition


    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

    =>

    (x2 - x1) * (y3 + y1) - (y1 - y2) * (x1 - x3)
    (x1 + x2 + x3) * (x1 - x3) * (x1 - x3) - (y3 + y1) * (y3 + y1)

*****************************************************************************************************************/

use algebra::FftField;
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
        [
            F::from(4 as u64) * &this[1].square() * &(this[2] + &this[0].double()) - F::from(9 as u64) * &this[0].square().square(),
            this[1].double() * &(this[3] + &this[1]) - F::from(3 as u64) * &this[0].square() * &(this[0] - &this[2]),
            this[1] * &this[6] - F::one(),

            (this[2] - &this[0]) * &(this[5] + &this[1]) - (this[1] - &this[3]) * &(this[0] - &this[4]),
            (this[0] + &this[2] + &this[4]) * &(this[0] - &this[4]).square() - (this[5] + &this[1]).square(),
            (this[2] - &this[0]) * &this[7] - F::one(),
        ].iter().all(|p| *p == F::zero())
    }

    pub fn double(&self) -> F {if self.typ == GateType::Double {F::one()} else {F::zero()}}
}
