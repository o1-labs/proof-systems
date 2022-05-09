//!
//! Common constraints and related helpers
//!

use ark_ff::{FftField, One};

use crate::circuits::expr::E;

pub(crate) fn two<F: FftField>() -> E<F> {
    2u64.into()
}

pub(crate) fn three<F: FftField>() -> E<F> {
    3u64.into()
}

// Crumb constraint for 2-bit sublimb
pub(crate) fn sublimb_crumb_constraint<F: FftField>(sublimb: &E<F>) -> E<F> {
    // Assert sublimb \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
    sublimb.clone()
        * (sublimb.clone() - E::one())
        * (sublimb.clone() - two())
        * (sublimb.clone() - three())
}
