//! This module contains the constraints for one Keccak step.
use crate::{
    interpreters::keccak::{
        helpers::{ArithHelpers, BoolHelpers, LogupHelpers},
        interpreter::{Interpreter, KeccakInterpreter},
        Constraint, KeccakColumn,
    },
    lookups::Lookup,
    E,
};
use ark_ff::{Field, One};
use kimchi::{
    circuits::{
        expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
        gate::CurrOrNext,
    },
    o1_utils::Two,
};
use kimchi_msm::columns::ColumnIndexer;

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

impl<F: Field> ArithHelpers<F> for Env<F> {
    fn two_pow(x: u64) -> Self::Variable {
        Self::constant_field(F::two_pow(x))
    }
}

impl<F: Field> BoolHelpers<F> for Env<F> {}

impl<F: Field> LogupHelpers<F> for Env<F> {}

impl<F: Field> Interpreter<F> for Env<F> {
    type Variable = E<F>;

    fn constant(x: u64) -> Self::Variable {
        Self::constant_field(F::from(x))
    }

    fn constant_field(x: F) -> Self::Variable {
        Self::Variable::constant(Operations::from(Literal(x)))
    }

    fn variable(&self, column: KeccakColumn) -> Self::Variable {
        // Despite `KeccakWitness` containing both `curr` and `next` fields,
        // the Keccak step spans across one row only.
        Expr::Atom(ExprInner::Cell(Variable {
            col: column.to_column(),
            row: CurrOrNext::Curr,
        }))
    }

    fn constrain(&mut self, _tag: Constraint, if_true: Self::Variable, x: Self::Variable) {
        if if_true == Self::Variable::one() {
            self.constraints.push(x);
        }
    }

    fn add_lookup(&mut self, if_true: Self::Variable, lookup: Lookup<Self::Variable>) {
        if if_true == Self::Variable::one() {
            self.lookups.push(lookup);
        }
    }
}

impl<F: Field> KeccakInterpreter<F> for Env<F> {}
