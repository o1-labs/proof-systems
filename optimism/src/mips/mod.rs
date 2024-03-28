//! This module implements a zero-knowledge virtual machine (zkVM) for the MIPS
//! architecture.
//! A zkVM is used by a prover to convince a verifier that the execution trace
//! (also called the `witness`) of a program execution is correct. In the case
//! of this zkVM, we will represent the execution trace by using a set of
//! columns whose values will represent the evaluations of polynomials over a
//! certain pre-defined domain. The correct execution will be proven using a
//! polynomial commitment protocol. The polynomials are described in the
//! structure [crate::mips::column::Column]. These polynomials will be
//! committed and evaluated at certain points following the polynomial protocol,
//! and it will form the proof of the correct execution that the prover will
//! build and send to the verifier. The corresponding structure is
//! [crate::proof::Proof]. The prover will start by computing the
//! execution trace using the interpreter implemented in the module
//! [crate::mips::interpreter], and the evaluations will be kept in the
//! structure [crate::proof::ProofInputs].

use self::column::Column;
use kimchi::circuits::expr::{ConstantExpr, Expr};

pub mod column;
pub mod constraints;
pub mod folding;
pub mod interpreter;
pub mod registers;
pub mod witness;

/// Type to represent a constraint on the individual columns of the execution
/// trace.
/// As a reminder, a constraint can be formally defined as a multi-variate
/// polynomial over a finite field. The variables of the polynomial are defined
/// as `crate::column::MIPSColumn`.
/// The `expression` framework defined in `kimchi::circuits::expr` is used to
/// describe the multi-variate polynomials.
/// For instance, a vanilla 3-wires PlonK constraint can be defined using the
/// multi-variate polynomial of degree 2
/// `P(X, Y, Z) = q_x X + q_y Y + q_m X Y + q_o Z + q_c`
/// To represent this multi-variate polynomial using the expression framework,
/// we would use 3 different columns.
pub(crate) type E<F> = Expr<ConstantExpr<F>, Column>;
