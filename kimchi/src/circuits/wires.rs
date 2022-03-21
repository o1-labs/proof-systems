//! This module implements Plonk circuit gate wires primitive.

use ark_ff::bytes::{FromBytes, ToBytes};
use array_init::array_init;
use serde::{Deserialize, Serialize};
use std::io::{Read, Result as IoResult, Write};

// Number of registers
//pub const COLUMNS: usize = 15;

/// New number of registers
pub const COLUMNS: usize = 40;

/// Number of registers that can be wired (participating in the permutation)
pub const PERMUTS: usize = 7;

/// index of all registers
pub const WIRES: [usize; COLUMNS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Wire documents the other cell that is wired to this one.
/// If the cell represents an internal wire, an input to the circuit,
/// or a final output of the circuit, the cell references itself.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
pub struct Wire {
    // TODO(mimoo): shouldn't we use u32 since we serialize them as u32?
    pub row: usize,
    pub col: usize,
}

impl Wire {
    /// Creates a new set of wires for a given row.
    pub fn new(row: usize) -> [Self; PERMUTS] {
        array_init(|col| Self { row, col })
    }
}

/// GateWires document the wiring of a gate. More specifically, each value either
/// represents the same cell (row and column) or a different cell in another row.
/// (This is to help the permutation argument.)
pub type GateWires = [Wire; PERMUTS];

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

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use std::convert::TryInto;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlWire {
        pub row: ocaml::Int,
        pub col: ocaml::Int,
    }

    impl From<Wire> for CamlWire {
        fn from(w: Wire) -> Self {
            Self {
                row: w.row.try_into().expect("usize -> isize"),
                col: w.col.try_into().expect("usize -> isize"),
            }
        }
    }

    impl From<CamlWire> for Wire {
        fn from(w: CamlWire) -> Self {
            Self {
                row: w.row.try_into().expect("isize -> usize"),
                col: w.col.try_into().expect("isize -> usize"),
            }
        }
    }
}

#[cfg(feature = "wasm_types")]
pub mod wasm {
    use super::*;

    #[wasm_bindgen::prelude::wasm_bindgen]
    impl Wire {
        #[wasm_bindgen::prelude::wasm_bindgen]
        pub fn create(row: i32, col: i32) -> Self {
            Self {
                row: row as usize,
                col: col as usize,
            }
        }
    }
}
