//! An argument is simply a number of constraints,
//! which we want to enforce on all points of the domain.
//! Both the permutation and the plookup arguments fit this type.
//! Gates can be seen as filtered arguments,
//! which apply only in some points (rows) of the domain.

use ark_ff::FftField;

use crate::{
    alphas::Alphas,
    circuits::expr::{ConstantExpr, Expr},
};

/// The interface for a minimal argument implementation
pub trait Argument {
    type Field: FftField;

    /// The number of constraints created by the argument
    const CONSTRAINTS: usize;

    /// Returns constraints safely combined via the passed combinator
    fn constraint(&self, combinator: &Alphas<Self::Field>) -> Expr<ConstantExpr<Self::Field>>;
}
