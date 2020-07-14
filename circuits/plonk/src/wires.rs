/*****************************************************************************************************************

This source file implements Plonk circuit gate wires primitive.

*****************************************************************************************************************/

#[derive(Clone, Copy)]
pub struct GateWires
{
    pub l: (usize, usize),  // left input wire index and its permutation
    pub r: (usize, usize),  // right input wire index and its permutation
    pub o: (usize, usize),  // output wire index and its permutation
}

impl GateWires
{
    pub fn wires
    (
        l: (usize, usize),
        r: (usize, usize),
        o: (usize, usize),
    ) -> Self
    {
        GateWires
        {
            l,
            r,
            o,
        }
    }
}
