/*****************************************************************************************************************

This source file implements Plonk generic constraint gate primitive.

*****************************************************************************************************************/

use ark_ff::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::wires::{COLUMNS, GateWires};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_generic
    (
        row: usize,
        wires: GateWires,
        qw: [F; COLUMNS],
        qm: F,
        qc: F,
    ) -> Self
    {
        let mut c = qw.to_vec();
        c.push(qm);
        c.push(qc);

        CircuitGate
        {
            row,
            typ: GateType::Generic,
            wires,
            c
        }
    }

    pub fn verify_generic(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        self.typ == GateType::Generic &&
        (
            (0..COLUMNS).map(|i| self.c[i] * &this[i]).fold(F::zero(), |x, y| x + &y) +
            &(self.c[COLUMNS] * &this[0] * &this[1]) +
            &self.c[COLUMNS + 1]
        ).is_zero()
    }
}
