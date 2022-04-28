//!
//! Fundamental constraints and related helpers
//!

use std::cell::RefCell;

use ark_ff::{FftField, One, Zero};

use crate::circuits::expr::{Cache, ConstantExpr, Expr, E};

thread_local! {
    static CACHE: std::cell::RefCell<Cache>  = RefCell::new(Cache::default());
}

pub(crate) fn _cache<F: FftField>(mut x: E<F>) -> E<F> {
    CACHE.with(|cache| x = cache.borrow_mut().cache(x.clone()));
    x
}

pub(crate) fn two<F: FftField>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(2u32.into()))
}

pub(crate) fn three<F: FftField>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(3u32.into()))
}

pub(crate) fn sublimb_plookup_constraint<F: FftField>(_sublimb: &E<F>) -> E<F> {
    // TODO: implement plookup constraint for 12-bit sublimb
    E::zero()
}

// Crumb constraint for 2-bit sublimb
pub(crate) fn sublimb_crumb_constraint<F: FftField>(sublimb: &E<F>) -> E<F> {
    // Assert sublimb \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
    sublimb.clone()
        * (sublimb.clone() - E::one())
        * (sublimb.clone() - two())
        * (sublimb.clone() - three())
}
