//! This module contains the constraints for one Keccak step.
use crate::{
    keccak::{KeccakColumn, E},
    lookups::{Lookup, LookupTableIDs},
};
use ark_ff::Field;
use kimchi::{
    circuits::{
        expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
        gate::CurrOrNext,
        polynomials::keccak::constants::RATE_IN_BYTES,
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
            col: column,
            row: CurrOrNext::Curr,
        }))
    }

    fn constrain(&mut self, x: Self::Variable) {
        self.constraints.push(x);
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }

    // TODO: optimize this by using a single lookup reusing PadSuffix
    fn lookup_syscall_preimage(&mut self) {
        for i in 0..RATE_IN_BYTES {
            self.add_lookup(Lookup::read_if(
                self.is_absorb(),
                LookupTableIDs::SyscallLookup,
                vec![
                    self.hash_index(),
                    self.block_index() * Self::constant(RATE_IN_BYTES as u64)
                        + Self::constant(i as u64),
                    self.sponge_byte(i),
                ],
            ));
        }
    }

    fn lookup_syscall_hash(&mut self) {
        let bytes31 = (1..32).fold(Self::zero(), |acc, i| {
            acc * Self::two_pow(8) + self.sponge_byte(i)
        });
        self.add_lookup(Lookup::write_if(
            self.is_squeeze(),
            LookupTableIDs::SyscallLookup,
            vec![self.hash_index(), bytes31],
        ));
    }

    fn lookup_steps(&mut self) {
        // (if not a root) Output of previous step is input of current step
        self.add_lookup(Lookup::read_if(
            Self::not(self.is_root()),
            LookupTableIDs::KeccakStepLookup,
            self.input_of_step(),
        ));
        // (if not a squeeze) Input for next step is output of current step
        self.add_lookup(Lookup::write_if(
            Self::not(self.is_squeeze()),
            LookupTableIDs::KeccakStepLookup,
            self.output_of_step(),
        ));
    }

    fn lookup_rc16(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTableIDs::RangeCheck16Lookup,
            vec![value],
        ));
    }

    fn lookup_reset(
        &mut self,
        flag: Self::Variable,
        dense: Self::Variable,
        sparse: Self::Variable,
    ) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTableIDs::ResetLookup,
            vec![dense, sparse],
        ));
    }

    fn lookup_sparse(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTableIDs::SparseLookup,
            vec![value],
        ));
    }

    fn lookup_byte(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTableIDs::ByteLookup,
            vec![value],
        ));
    }

    fn lookup_pad(&mut self, flag: Self::Variable, value: Vec<Self::Variable>) {
        self.add_lookup(Lookup::read_if(flag, LookupTableIDs::PadLookup, value));
    }

    fn lookup_round_constants(&mut self, flag: Self::Variable, value: Vec<Self::Variable>) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTableIDs::RoundConstantsLookup,
            value,
        ));
    }
}
