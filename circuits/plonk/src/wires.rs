/*****************************************************************************************************************

This source file implements Plonk circuit gate wires primitive.

*****************************************************************************************************************/

pub const COLUMNS: usize = 5;
pub const WIRES: [usize; COLUMNS] = [0,1,2,3,4];

pub type GateWires = [(usize, usize); COLUMNS];

#[derive(Clone, Copy)]
pub struct Wire
{
    pub row: usize,
    pub col: usize,
}

#[derive(Clone, Copy)]
pub struct Wires
{
    pub row: usize,
    pub wires: [Wire; COLUMNS]
}
