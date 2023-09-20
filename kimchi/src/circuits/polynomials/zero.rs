//! Zero gate
//!
//! This gate implements nothing

use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::{circuits::{
    argument::{ArgumentEnv, Gate},
    expr::{constraints::ExprOps, Cache},
}, define_gate};

define_gate!(Zero<F: PrimeField>, "Implements the empty gate without any constraints");

impl<F: PrimeField, T: ExprOps<F>> Gate<F, T> for Zero<F> {
    fn name(&self) -> &str {
        "Zero"
    }

    fn constraint_checks(
        &self,
        env: &ArgumentEnv<F, T>,
        cache: &mut Cache,
    ) -> Vec<T> {
        vec![]
    }
}
