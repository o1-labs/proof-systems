/*****************************************************************************************************************

This source file implements Plonk computation wire index primitive.

*****************************************************************************************************************/

use algebra::Field;

#[derive(Clone)]
pub struct CircuitGate<F: Field>
{
    pub l: (usize, usize),   // left input wire index and its permutation
    pub r: (usize, usize),   // right input wire index and its permutation
    pub o: (usize, usize),   // output wire index and its permutation

    pub ql: F, // left input
    pub qr: F, // right input
    pub qo: F, // output
    pub qm: F, // multiplication
    pub qc: F, // constant
}

impl<F: Field> CircuitGate<F>
{
    // this function creates "empty" circuit gate
    pub fn zero () -> Self
    {
        CircuitGate
        {
            l: (0, 0),
            r: (0, 0),
            o: (0, 0),
            ql: F::zero(),
            qr: F::zero(),
            qo: F::zero(),
            qm: F::zero(),
            qc: F::zero(),
        }
    }

    pub fn create
    (
        l: (usize, usize),
        r: (usize, usize),
        o: (usize, usize),
        ql: F,
        qr: F,
        qo: F,
        qm: F,
        qc: F,
    ) -> Self
    {
        CircuitGate
        {
            l,
            r,
            o,
            ql,
            qr,
            qo,
            qm,
            qc,
        }
    }
}
