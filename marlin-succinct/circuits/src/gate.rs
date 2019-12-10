/*****************************************************************************************************************

This source file implements Marlin computation circuit gate primitive.

Marlin factors out the linear relations for the computation into the system of linear constraints. The
computation circuit, modulo the linear relations, consists of multiplicative gates that have two inputs
and one output:

Left input A
Right input B
Output C

*****************************************************************************************************************/

use algebra::{Field, PrimeField};

#[derive(Clone)]
pub struct CircuitGate<F: Field>
{
    pub wire: [F; 3], // left input wire, right input wire, output wire
}

impl<F: PrimeField> CircuitGate<F>
{
    // This function creates zero-instance circuit gate
    pub fn zero() -> Self
    {
        CircuitGate::<F>
        {
            wire : [F::zero(), F::zero(), F::zero()]
        }
    }
    // This function creates one-instance circuit gate
    pub fn one() -> Self
    {
        CircuitGate::<F>
        {
            wire : [F::one(), F::one(), F::one()]
        }
    }
}
