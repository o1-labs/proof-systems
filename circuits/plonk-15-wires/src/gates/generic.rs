/*****************************************************************************************************************

This source file implements Plonk generic constraint gate primitive.

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use algebra::FftField;
use array_init::array_init;

impl<F: FftField> CircuitGate<F> {
    pub fn create_generic(row: usize, wires: GateWires, qw: [F; COLUMNS], qm: F, qc: F) -> Self {
        let mut c = qw.to_vec();
        c.push(qm);
        c.push(qc);

        CircuitGate {
            row,
            typ: GateType::Generic,
            wires,
            c,
        }
    }

    pub fn verify_generic(&self, witness: &[Vec<F>; COLUMNS]) -> bool {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        // assignments
        let left = this[0];
        let right = this[1];

        // selector vectors
        let mul_selector = self.c[COLUMNS];
        let constant_selector = self.c[COLUMNS + 1];

        // constants
        let zero = F::zero();

        // check if it's the correct gate
        ensure_eq!(self.typ, GateType::Generic);

        // toggling each column x[i] depending on the selectors c[i]
        // TODO(mimoo): why involve an addition with all columns?
        let big_sum = (0..COLUMNS)
            .map(|i| self.c[i] * &this[i])
            .fold(F::zero(), |x, y| x + &y);

        // multiplication selector c[15] is for x[0] and x[1]
        let mul = mul_selector * &left * &right;

        // TODO(mimoo): what about the output?
        ensure_eq!(zero, big_sum + &mul + &constant_selector);

        // all good
        return true;
    }
}
