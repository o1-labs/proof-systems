//! Lookup gate
//!
//! This gate is implements the lookup gate type

use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::{
    circuits::{
        argument::ArgumentEnv,
        expr::{constraints::ExprOps, Cache},
        gate::Gate,
    },
    define_gate,
};

define_gate!(Lookup<F: PrimeField>, "Implements the lookup gate type");

impl<F: PrimeField, T: ExprOps<F>> Gate<F, T> for Lookup<F> {
    fn constraint_checks(&self, env: &ArgumentEnv<F, T>, cache: &mut Cache) -> Vec<T> {
        vec![]
    }
}
