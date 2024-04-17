//! This module contains the constraints for one Keccak step.
use crate::{
    keccak::{
        column::{
            Absorbs::*,
            Sponges::*,
            Steps::{self, *},
        },
        helpers::{ArithHelpers, BoolHelpers, LogupHelpers},
        interpreter::{Interpreter, KeccakInterpreter},
        Constraint, KeccakColumn, Selector,
    },
    lookups::Lookup,
    E,
};
use ark_ff::{Field, One, Zero};
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
    /// Selector of the current step, corresponds to a Keccak step or None if it just ended or still hasn't started
    pub step: Option<Steps>,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            constraints: Vec::new(),
            lookups: Vec::new(),
            step: None,
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

impl<F: Field> KeccakInterpreter<F> for Env<F> {
    fn check(&mut self, _tag: Selector, _x: <Env<F> as Interpreter<F>>::Variable) {
        // No-op in constraint side
    }

    fn checks(&mut self) {
        // No-op in constraint side
    }

    fn mode_absorb(&self) -> <Env<F> as Interpreter<F>>::Variable {
        match self.step {
            Some(Sponge(Absorb(Middle))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_squeeze(&self) -> <Env<F> as Interpreter<F>>::Variable {
        match self.step {
            Some(Sponge(Squeeze)) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_root(&self) -> <Env<F> as Interpreter<F>>::Variable {
        match self.step {
            Some(Sponge(Absorb(First))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_pad(&self) -> <Env<F> as Interpreter<F>>::Variable {
        match self.step {
            Some(Sponge(Absorb(Last))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_rootpad(&self) -> <Env<F> as Interpreter<F>>::Variable {
        match self.step {
            Some(Sponge(Absorb(Only))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_round(&self) -> <Env<F> as Interpreter<F>>::Variable {
        // The actual round number in the selector carries no information for witness nor constraints
        // because in the witness, any usize is mapped to the same index inside the mode flags
        match self.step {
            Some(Round(_)) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
}
