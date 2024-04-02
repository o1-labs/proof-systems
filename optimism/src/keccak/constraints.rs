//! This module contains the constraints for one Keccak step.
use crate::{
    keccak::{
        column::{
            Absorbs::*,
            Flags::{self, *},
            Sponges::*,
        },
        Constraint, KeccakColumn, Selector, E,
    },
    lookups::Lookup,
};
use ark_ff::{Field, One, Zero};
use kimchi::{
    circuits::{
        expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
        gate::CurrOrNext,
    },
    o1_utils::Two,
};

use super::interpreter::KeccakInterpreter;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
#[derive(Clone, Debug)]
pub struct Env<Fp> {
    /// Constraints that are added to the circuit
    pub constraints: Vec<E<Fp>>,
    /// Variables that are looked up in the circuit
    pub lookups: Vec<Lookup<E<Fp>>>,
    /// Selector of the current step
    pub(crate) selector: Option<Flags>,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            constraints: Vec::new(),
            lookups: Vec::new(),
            selector: None,
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
            col: column,
            row: CurrOrNext::Curr,
        }))
    }

    fn check(&mut self, _tag: Selector, _x: Self::Variable) {
        // No-op in constraint side
    }

    fn checks(&mut self) {
        // No-op in constraint side
    }

    fn constrain(&mut self, _tag: Constraint, if_true: Self::Variable, x: Self::Variable) {
        if if_true == Self::Variable::one() {
            self.constraints.push(x);
        }
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }

    /////////////////////////
    // SELECTOR OPERATIONS //
    /////////////////////////

    fn mode_absorb(&self) -> Self::Variable {
        match self.selector {
            Some(Sponge(Absorb(Middle))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_squeeze(&self) -> Self::Variable {
        match self.selector {
            Some(Sponge(Squeeze)) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_root(&self) -> Self::Variable {
        match self.selector {
            Some(Sponge(Absorb(First))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_pad(&self) -> Self::Variable {
        match self.selector {
            Some(Sponge(Absorb(Last))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_rootpad(&self) -> Self::Variable {
        match self.selector {
            Some(Sponge(Absorb(Only))) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
    fn mode_round(&self) -> Self::Variable {
        match self.selector {
            Some(Round) => Self::Variable::one(),
            _ => Self::Variable::zero(),
        }
    }
}
