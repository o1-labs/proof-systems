// TODO: uncomment
// #![deny(missing_docs)]

//! Snarky is the front end to kimchi, allowing users to write their own programs and convert them to kimchi circuits.
//!
//! See the Mina book for more detail about this implementation.
//!
//! See the `tests.rs` file for examples of how to use snarky.

pub mod api;
pub mod asm;
pub mod boolean;
pub mod constants;
pub mod constraint_system;
pub mod cvar;
pub mod errors;
pub mod folding;
pub mod poseidon;
pub(crate) mod range_checks;
pub mod runner;
pub mod snarky_type;
pub mod union_find;

#[cfg(test)]
mod tests;

/// A handy module that you can import the content of to easily use snarky.
pub mod prelude {
    use super::*;
    pub use crate::loc;
    pub use cvar::FieldVar;
    pub use errors::SnarkyResult;
    pub use runner::RunState;
}
