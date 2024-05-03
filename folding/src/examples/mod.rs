//! This module provides examples on how to use the different submodules of the library.
//! The examples are meant to be run with the `cargo nextest` command.
//! The user is encouraged to read the code and understand the different steps of the protocol.
//! The examples are built over a generic type of columns and selectors.
//! The user is encouraged to start reading this module and then move to the
//! modules specialised for the different folding implementations.
//!
//! The examples are generic enough to be reused externally. The users can copy the
//! code and adapt it to their needs. The generic structures are defined in the
//! `generic` module.

mod example;
mod example_decomposable_folding;
mod example_quadriticization;

/// Define the different structures requires for the examples.
mod generic;
