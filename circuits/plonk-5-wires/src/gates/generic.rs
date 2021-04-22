/*****************************************************************************************************************

This source file implements Plonk generic constraint gate primitive.

*****************************************************************************************************************/

use algebra::FftField;
use crate::gate::{CircuitGate};
use crate::wires::{COLUMNS, GateWires};
use array_init::array_init;

pub trait GenericGateType : PartialEq
{
    const GENERIC: Self;
}

impl<F: FftField, GateType: GenericGateType> CircuitGate<F, GateType>
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
            typ: GateType::GENERIC,
            wires,
            c
        }
    }

    pub fn verify_generic(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        self.typ == GateType::GENERIC &&
        (
            (0..COLUMNS).map(|i| self.c[i] * &this[i]).fold(F::zero(), |x, y| x + &y) +
            &(self.c[COLUMNS] * &this[0] * &this[1]) +
            &self.c[COLUMNS + 1]
        ).is_zero()
    }
}
