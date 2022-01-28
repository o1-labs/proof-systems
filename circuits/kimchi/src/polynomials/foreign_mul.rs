// Foreign field multiplication

use crate::expr::{Cache, Column, ConstantExpr, E};
use crate::gate::{CurrOrNext, GateType};
use crate::wires::COLUMNS;
use ark_ff::{Field, One};
use CurrOrNext::*;

/// The constraints for foreign field multiplication
pub fn constraints<F: Field>() -> Vec<E<F>> {
    let v = |c| E::cell(c, Curr);
    let w = |i| v(Column::Witness(i));

    println!("w(0) = {:?}", w(0));
    println!("w(1) = {:?}", w(1));

    //
    // Compute t such that 2^t*n > p^2 + p
    //     t  = log2(p^2 - p) - log2(n) + 1
    //     p' = -p

    vec![w(11)]
}

/// The combined constraint for foreign field multiplication
pub fn constraint<F: Field>(alpha0: usize) -> E<F> {
    E::combine_constraints(alpha0, constraints()) * E::cell(Column::Index(GateType::ForeignMul0), Curr)
}
