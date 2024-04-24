//! This module implements a zero-knowledge virtual machine (zkVM) for the MIPS
//! architecture.
//! A zkVM is used by a prover to convince a verifier that the execution trace
//! (also called the `witness`) of a program execution is correct. In the case
//! of this zkVM, we will represent the execution trace by using a set of
//! columns whose values will represent the evaluations of polynomials over a
//! certain pre-defined domain. The correct execution will be proven using a
//! polynomial commitment protocol. The polynomials are described in the
//! structure [crate::mips::column::ColumnAlias]. These polynomials will be
//! committed and evaluated at certain points following the polynomial protocol,
//! and it will form the proof of the correct execution that the prover will
//! build and send to the verifier. The corresponding structure is
//! Proof. The prover will start by computing the
//! execution trace using the interpreter implemented in the module
//! [crate::mips::interpreter], and the evaluations will be kept in the
//! structure ProofInputs.

pub mod column;
pub mod constraints;
#[cfg(feature = "bn254")]
pub mod folding;
pub mod interpreter;
pub mod registers;
#[cfg(test)]
pub mod tests;
pub mod trace;
pub mod witness;

pub use interpreter::{ITypeInstruction, Instruction, JTypeInstruction, RTypeInstruction};
