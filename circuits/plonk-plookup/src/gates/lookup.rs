/*****************************************************************************************************************

This source file implements lookup constraint gate Plonk primitive.

The wires are:

0. function opcode (1 : 7)
1. output
2. input
3. input
4. lookup value

Lookup gate constrains:

XOR8:
    (w0 - 1) * (w0 - 2) * (w0 - 3) * (w0 - 4) * (w0 - 5) * (w0 - 6) * (w0 - 7) = 0
    w4 = w0 + w1*(2^4) + w2*(2^12) + w3*(2^20) 

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
        F::zero() == (2..8).fold(w[0] - &F::one(), |x, i| x * &(w[0]-F::from(i as u64)))
        &&
        w[4] ==
            w[0] +
            &(w[1] * &F::from(16 as u64)) +
            &(w[2] * &F::from(4096 as u64)) +
            &(w[3] * &F::from(1048576 as u64))
    }
    
    pub fn lookup(&self) -> F {if self.typ == GateType::Lookup {F::one()} else {F::zero()}}
}
