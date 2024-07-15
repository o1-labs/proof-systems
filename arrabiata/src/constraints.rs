use ark_ff::Field;

use crate::columns::E;

use super::{columns::Column, interpreter::InterpreterEnv};

pub struct Env<Fp: Field> {
    pub constraints: Vec<E<Fp>>,
}

/// An environment to build constraints.
/// The constraint environment is mostly useful when we want to perform a Nova
/// proof.
/// The constraint environment must be instantiated only once, at the last step
/// of the computation.
impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Position = Column;

    type Variable = E<Fp>;
}
