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

impl<Field: FftField> CircuitGate<Field> {
    /// Creates an ECC add gate. Warning: this assumes that the two points are:
    /// - on the curve
    /// - not mutual inverses (e.g. P and -P)
    /// - not the same point (e.g. P and P)
    pub fn create_add(row: usize, wires: GateWires) -> Self {
        CircuitGate {
            row,
            typ: GateType::Add,
            wires,
            c: vec![],
        }
    }

    /// Given a set of [witness] over an Add gate, verify that the constraints checks out.
    pub fn verify_add(&self, witness: &[Vec<Field>; COLUMNS]) -> bool {
        let this: [Field; COLUMNS] = array_init(|i| witness[i][self.row]);

        let x1 = this[0];
        let y1 = this[1];
        let x2 = this[2];
        let y2 = this[3];
        let x3 = this[4];
        let y3 = this[5];
        let r = this[6];

        let zero = Field::zero();
        let one = Field::one();

        if self.typ != GateType::Add {
            return false;
        }
        if (x2 - x1) * (y3 + y1) - (y2 - y1) * (x1 - x3) != zero {
            return false;
        }
        if (x1 + x2 + x3) * (x1 - x3).square() - (y3 + y1).square() != zero {
            return false;
        }
        if (x2 - x1) * r - one != zero {
            return false;
        }

        return true;
    }

    /// Returns 1 if [self] is an [GateType::Add] gate, 0 otherwise.
    pub fn add(&self) -> Field {
        if self.typ == GateType::Add {
            Field::one()
        } else {
            Field::zero()
        }
    }
}
