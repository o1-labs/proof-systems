//! This module contains the constraints for one Keccak step.
use crate::{
    keccak::{Constraint, KeccakColumn},
    lookups::Lookup,
    E,
};
use ark_ff::Field;
use kimchi::{
    circuits::{
        expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
        gate::CurrOrNext,
    },
    o1_utils::Two,
};
use kimchi_msm::columns::ColumnIndexer;

use super::interpreter::KeccakInterpreter;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
#[derive(Clone, Debug)]
pub struct Env<Fp> {
    /// Constraints that are added to the circuit
    pub constraints: Vec<E<Fp>>,
    /// Variables that are looked up in the circuit
    pub lookups: Vec<Lookup<E<Fp>>>,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            constraints: Vec::new(),
            lookups: Vec::new(),
        }
    }
}

impl<F: Field> KeccakInterpreter<F> for Env<F> {
    type Variable = E<F>;

    ///////////////////////////
    // ARITHMETIC OPERATIONS //
    ///////////////////////////

    fn constant(x: u64) -> Self::Variable {
        Self::constant_field(F::from(x))
    }

    fn constant_field(x: F) -> Self::Variable {
        Self::Variable::constant(Operations::from(Literal(x)))
    }

    fn two_pow(x: u64) -> Self::Variable {
        Self::constant_field(F::two_pow(x))
    }

    ////////////////////////////
    // CONSTRAINTS OPERATIONS //
    ////////////////////////////

    fn variable(&self, column: KeccakColumn) -> Self::Variable {
        // Despite `KeccakWitness` containing both `curr` and `next` fields,
        // the Keccak step spans across one row only.
        Expr::Atom(ExprInner::Cell(Variable {
            col: column.to_column(),
            row: CurrOrNext::Curr,
        }))
    }

    fn constrain(&mut self, _tag: Constraint, x: Self::Variable) {
        self.constraints.push(x);
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }
}
