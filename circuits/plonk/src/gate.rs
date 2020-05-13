/*****************************************************************************************************************

This source file implements Plonk computation wire index primitive.

*****************************************************************************************************************/

#[derive(Clone)]
pub struct CircuitGate
{
    pub l: usize,   // left input wire index
    pub r: usize,   // right input wire index
    pub o: usize,   // output wire index
}

impl CircuitGate 
{
    // this function creates "empty" circuit gate
    pub fn zero () -> Self
    {
        CircuitGate
        {
            l: 0,
            r: 0,
            o: 0,
        }
    }
}
