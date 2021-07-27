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

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use algebra::FftField;
use array_init::array_init;

impl<F: FftField> CircuitGate<F> {
    pub fn create_double(row: usize, wires: GateWires) -> Self {
        CircuitGate {
            row,
            typ: GateType::Double,
            wires,
            c: vec![],
        }
    }

    pub fn verify_double(&self, witness: &[Vec<F>; COLUMNS]) -> bool {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        let this0 = this[0];
        let this1 = this[1];
        let this2 = this[2];
        let this3 = this[3];
        let this4 = this[4];
        let this5 = this[5];
        let this6 = this[6];
        let this7 = this[7];

        let zero = F::zero();
        let one = F::one();
        let three = F::from(3 as u64);
        let four = F::from(4 as u64);
        let nine = F::from(9 as u64);

        ensure_eq!(self.typ, GateType::Double);

        ensure_eq!(
            zero,
            four * &this1.square() * &(this2 + &this0.double()) - nine * &this0.square().square()
        );

        ensure_eq!(
            zero,
            this1.double() * &(this3 + &this1) - three * &this0.square() * &(this0 - &this2)
        );

        ensure_eq!(zero, this1 * &this6 - one);

        ensure_eq!(
            zero,
            (this2 - &this0) * &(this5 + &this1) - (this1 - &this3) * &(this0 - &this4)
        );

        ensure_eq!(
            zero,
            (this0 + &this2 + &this4) * &(this0 - &this4).square() - (this5 + &this1).square()
        );

        ensure_eq!(zero, (this2 - &this0) * &this7 - one);

        // all good
        return true;
    }

    pub fn double(&self) -> F {
        if self.typ == GateType::Double {
            F::one()
        } else {
            F::zero()
        }
    }
}
