/*****************************************************************************************************************

This source file implements Plonk computation wire index primitive.

*****************************************************************************************************************/

use algebra::Field;

#[derive(Clone)]
pub struct CircuitGate<F: Field>
{
    pub l: usize,   // left input wire index
    pub r: usize,   // right input wire index
    pub o: usize,   // output wire index

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
            l: 0,
            r: 0,
            o: 0,
            ql: F::zero(),
            qr: F::zero(),
            qo: F::zero(),
            qm: F::zero(),
            qc: F::zero(),
        }
    }

    pub fn create
    (
        l: usize,
        r: usize,
        o: usize,
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