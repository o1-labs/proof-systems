#![warn(missing_docs)]
//! This module contains the code that executes a compiled Cairo program and generates the memory.
//! The Cairo runner includes code to execute a bytecode compiled Cairo program,
//! and obtain a memory instantiation after the execution. It uses some code to
//! represent Cairo instructions and their decomposition, together with their logic
//! which is represented as steps of computation making up the full program.
pub mod flags;
pub mod helper;
pub mod memory;
pub mod runner;
pub mod word;
