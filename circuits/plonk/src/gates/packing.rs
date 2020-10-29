/*****************************************************************************************************************

This source file implements packing constraint gate Plonk primitive.

PACK gate constrains
    si = s1,i + 2*s2,i + 4*s3,i + 8*s4,i + 16*si+1
    s1,i * (s1,i – 1) = 0

*****************************************************************************************************************/

use algebra::FftField;
use crate::wires::{GateWires, COLUMNS};
use crate::gate::{CircuitGate, GateType};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_pack(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::Pack,
            wires,
            c: vec![]
        }
    }

    pub fn verify_pack(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][self.row+1]);

        self.typ == GateType::Pack
        &&
        this[4] ==
            this[0] +
            &this[1].double() +
            &this[2].double().double() +
            &this[3].double().double().double() +
            &next[4].double().double().double().double()
        &&
        // verify booleanity of the scalar bits
        !(0..COLUMNS-1).map(|i| this[i]).any(|b| b != b.square())
    }

    pub fn pack(&self) -> F {if self.typ == GateType::Pack {F::one()} else {F::zero()}}
}
