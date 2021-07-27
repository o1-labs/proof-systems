/*****************************************************************************************************************

This source file implements Plonk circuit gate wires primitive.

*****************************************************************************************************************/

use algebra::bytes::{FromBytes, ToBytes};
use std::io::{Read, Result as IoResult, Write};

pub const GENERICS: usize = 3;
pub const COLUMNS: usize = 15;
pub const PERMUTS: usize = 7;
pub const WIRES: [usize; COLUMNS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Wire documents the other cell that is wired to this one.
/// If the cell represents an internal wire, an input to the circuit,
/// or a final output of the circuit, the cell references itself.
#[derive(Clone, Copy)]
pub struct Wire {
    // TODO(mimoo): shouldn't we use u32 since we serialize them as u32?
    pub row: usize,
    pub col: usize,
}

/// GateWires document the wiring of a gate. More specifically, each value either
/// represents the same cell (row and column) or a different cell in another row.
/// (This is to help the permutation argument.)
pub type GateWires = [Wire; COLUMNS];

impl ToBytes for Wire {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        (self.row as u32).write(&mut w)?;
        (self.col as u32).write(&mut w)?;
        Ok(())
    }
}

impl FromBytes for Wire {
    #[inline]
    fn read<R: Read>(mut r: R) -> IoResult<Self> {
        let row = u32::read(&mut r)? as usize;
        let col = u32::read(&mut r)? as usize;
        Ok(Wire { row, col })
    }
}
