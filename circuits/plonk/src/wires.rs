/*****************************************************************************************************************

This source file implements Plonk circuit gate wires primitive.

*****************************************************************************************************************/

#[derive(Clone, Copy)]
#[derive(Debug)]
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

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum Col {L, R, O}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct Wire
{
    pub row: usize,         // wire row
    pub col: Col,           // wire column
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct Wires
{
    pub row: usize,         // gate wire row
    pub l: Wire,            // left input wire permutation
    pub r: Wire,            // right input wire permutation
    pub o: Wire,            // output input wire permutation
}
