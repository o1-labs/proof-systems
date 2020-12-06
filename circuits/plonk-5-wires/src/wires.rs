/*****************************************************************************************************************

This source file implements Plonk circuit gate wires primitive.

*****************************************************************************************************************/

pub const COLUMNS: usize = 5;
pub const WIRES: [usize; COLUMNS] = [0,1,2,3,4];

#[derive(Clone, Copy)]
pub struct Wire
{
    pub row: usize,
    pub col: usize,
}

pub type GateWires = [Wire; COLUMNS];

#[derive(Clone, Copy)]
pub struct Wires
{
    pub row: usize,
    pub wires: GateWires,
}
