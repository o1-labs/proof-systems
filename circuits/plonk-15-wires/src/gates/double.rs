/*****************************************************************************************************************

This source file implements constraints for non-special point doubling on Weierstrass curve

DOUBLE gate constrains

	4 * y1^2 * (x2 + 2*x1) = 9 * x1^4
	2 * y1 * (y2 + y1) = (3 * x1^2) * (x1 – x2)
	y1 * r1 = 1
	4 * y2^2 * (x4 + 2*x2) = 9 * x2^4
	2 * y2 * (y4 + y2) = (3 * x2^2) * (x2 – x4)
	y2 * r2 = 1
	4 * y4^2 * (x8 + 2*x4) = 9 * x4^4
	2 * y4 * (y8 + y4) = (3 * x4^2) * (x4 – x8)
	y4 * r3 = 1
	4 * y8^2 * (x16 + 2*x8) = 9 * x8^4
	2 * y8 * (y16 + y8) = (3 * x8^2) * (x8 – x16)
	y8 * r4 = 1

The constrains above are derived from the following EC Affine arithmetic equations:

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
        F::from(4 as u64) * &this[1].square() * &(this[2] + &this[0].double())
        ==
        F::from(9 as u64) * &this[0].square().square()
        &&
        this[1].double() * &(this[3] + &this[1])
        ==
        F::from(3 as u64) * &this[0].square() * &(this[0] - &this[2])
        &&
        this[1] * &this[10] == F::one()
        &&
        F::from(4 as u64) * &this[3].square() * &(this[6] + &this[2].double())
        ==
        F::from(9 as u64) * &this[2].square().square()
        &&
        this[3].double() * &(this[7] + &this[3])
        ==
        F::from(3 as u64) * &this[2].square() * &(this[2] - &this[6])
        &&
        this[3] * &this[11] == F::one()
        &&
        F::from(4 as u64) * &this[7].square() * &(this[8] + &this[6].double())
        ==
        F::from(9 as u64) * &this[6].square().square()
        &&
        this[7].double() * &(this[9] + &this[7])
        ==
        F::from(3 as u64) * &this[6].square() * &(this[6] - &this[8])
        &&
        this[7] * &this[12] == F::one()
        &&
        F::from(4 as u64) * &this[9].square() * &(this[4] + &this[8].double())
        ==
        F::from(9 as u64) * &this[8].square().square()
        &&
        this[9].double() * &(this[5] + &this[9])
        ==
        F::from(3 as u64) * &this[8].square() * &(this[8] - &this[4])
        &&
        this[9] * &this[13] == F::one()
    }

    pub fn double(&self) -> F {if self.typ == GateType::Double {F::one()} else {F::zero()}}
}
