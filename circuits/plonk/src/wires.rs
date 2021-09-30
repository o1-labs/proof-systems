/*****************************************************************************************************************

This source file implements Plonk circuit gate wires primitive.

*****************************************************************************************************************/

use algebra::bytes::{FromBytes, ToBytes};
use std::io::{Read, Result as IoResult, Write};

#[derive(Clone, Copy, Debug)]
pub struct GateWires {
    pub l: (usize, usize), // left input wire index and its permutation
    pub r: (usize, usize), // right input wire index and its permutation
    pub o: (usize, usize), // output wire index and its permutation
}

impl ToBytes for GateWires {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        (self.l.0 as u32).write(&mut w)?;
        (self.l.1 as u32).write(&mut w)?;
        (self.r.0 as u32).write(&mut w)?;
        (self.r.1 as u32).write(&mut w)?;
        (self.o.0 as u32).write(&mut w)?;
        (self.o.1 as u32).write(&mut w)?;
        Ok(())
    }
}

impl FromBytes for GateWires {
    #[inline]
    fn read<R: Read>(mut r: R) -> IoResult<Self> {
        let l0 = u32::read(&mut r)? as usize;
        let l1 = u32::read(&mut r)? as usize;
        let r0 = u32::read(&mut r)? as usize;
        let r1 = u32::read(&mut r)? as usize;
        let o0 = u32::read(&mut r)? as usize;
        let o1 = u32::read(&mut r)? as usize;
        Ok(GateWires {
            l: (l0, l1),
            r: (r0, r1),
            o: (o0, o1),
        })
    }
}

impl GateWires {
    pub fn wires(l: (usize, usize), r: (usize, usize), o: (usize, usize)) -> Self {
        GateWires { l, r, o }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum Col {
    L,
    R,
    O,
}

#[derive(Clone, Copy, Debug)]
pub struct Wire {
    pub row: usize, // wire row
    pub col: Col,   // wire column
}

#[derive(Clone, Copy, Debug)]
pub struct Wires {
    pub row: usize, // gate wire row
    pub l: Wire,    // left input wire permutation
    pub r: Wire,    // right input wire permutation
    pub o: Wire,    // output input wire permutation
}
