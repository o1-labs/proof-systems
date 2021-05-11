/*****************************************************************************************************************

This source file implements lookup constraint gate Plonk primitive.

The wires are:

0. function opcode
1. output
2. input
3. input
4. lookup value

Lookup gate constrains:

XOR8:
    w4 = w0 + w1*(2^8) + w2*(2^16) + w3*(2^24) 

*****************************************************************************************************************/

use algebra::FftField;
use crate::wires::{GateWires, COLUMNS};
use crate::gate::{CircuitGate, GateType};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_lookup(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::Lookup,
            wires,
            c: vec![]
        }
    }

    pub fn verify_lookup(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let w: [F; COLUMNS] = array_init(|i| witness[i][self.row]);

        self.typ == GateType::Lookup
        &&
        w[4] ==
            w[0] +
            &(w[1] * &F::from(0x100 as u64)) +
            &(w[2] * &F::from(0x10000 as u64)) +
            &(w[3] * &F::from(0x1000000 as u64))
    }
    
    pub fn lookup(&self) -> F {if self.typ == GateType::Lookup {F::one()} else {F::zero()}}
}
