//! This module implements Plonk circuit gate wires primitive.

use core::array;
use serde::{Deserialize, Serialize};

/// Number of registers
pub const COLUMNS: usize = 15;

/// Number of registers that can be wired (participating in the permutation)
pub const PERMUTS: usize = 7;

/// index of all registers
pub const WIRES: [usize; COLUMNS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Wire documents the other cell that is wired to this one.
/// If the cell represents an internal wire, an input to the circuit,
/// or a final output of the circuit, the cell references itself.
#[derive(PartialEq, Default, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
pub struct Wire {
    // TODO(mimoo): shouldn't we use u32 since we serialize them as u32?
    pub row: usize,
    pub col: usize,
}

impl Wire {
    /// Creates a new [Wire].
    pub fn new(row: usize, col: usize) -> Self {
        Self { row, col }
    }

    /// Creates a new set of wires for a given row.
    pub fn for_row(row: usize) -> [Self; PERMUTS] {
        GateWires::new(row)
    }
}

/// `GateWires` document the wiring of a gate. More specifically, each value either
/// represents the same cell (row and column) or a different cell in another row.
/// (This is to help the permutation argument.)
pub type GateWires = [Wire; PERMUTS];

/// Since we don't have a specific type for the wires of a row,
/// we have to implement these convenience functions through a trait.
pub trait Wirable: Sized {
    /// Creates a new set of wires for a given row.
    fn new(row: usize) -> Self;

    /// Wire the cell at `col` to another cell (`to`).
    fn wire(self, col: usize, to: Wire) -> Self;
}

impl Wirable for GateWires {
    fn new(row: usize) -> Self {
        array::from_fn(|col| Wire { row, col })
    }

    fn wire(mut self, col: usize, to: Wire) -> Self {
        assert!(col < PERMUTS);
        self[col] = to;
        self
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use core::convert::TryInto;

    #[derive(ocaml::ToValue, ocaml::FromValue, ocaml_gen::Struct)]
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
