//! This file contains the witness for the Keccak hash function for the zkVM project.
//! It assigns the witness values to the corresponding columns of KeccakWitness in the environment.
//!
//! The actual witness generation code makes use of the code which is already present in Kimchi,
//! to avoid code duplication and reduce error-proneness.
//!
//! For a pseudo code implementation of Keccap-f, see
//! <https://keccak.team/keccak_specs_summary.html>
use crate::{
    keccak::{
        column::KeccakWitness, interpreter::KeccakInterpreter, Constraint, Error, KeccakColumn,
    },
    lookups::Lookup,
};
use ark_ff::Field;
use kimchi::o1_utils::Two;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
#[derive(Clone, Debug)]
pub struct Env<Fp> {
    /// The full state of the Keccak gate (witness)
    pub witness: KeccakWitness<Fp>,
    // The multiplicities of each lookup table
    // TODO
    /// If any, an error that occurred during the execution of the constraints, to help with debugging
    pub(crate) errors: Vec<Error>,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            witness: KeccakWitness::default(),
            errors: vec![],
        }
    }
}

impl<F: Field> KeccakInterpreter<F> for Env<F> {
    type Variable = F;
    ///////////////////////////
    // ARITHMETIC OPERATIONS //
    ///////////////////////////

    fn constant(x: u64) -> Self::Variable {
        Self::constant_field(F::from(x))
    }

    fn constant_field(x: F) -> Self::Variable {
        x
    }

    fn two_pow(x: u64) -> Self::Variable {
        Self::constant_field(F::two_pow(x))
    }

    ////////////////////////////
    // CONSTRAINTS OPERATIONS //
    ////////////////////////////

    fn variable(&self, column: KeccakColumn) -> Self::Variable {
        self.witness[column]
    }

    /// Assert that the input is zero
    fn constrain(&mut self, tag: Constraint, x: Self::Variable) {
        if x != F::zero() {
            self.errors.push(Error::Constraint(tag));
        }
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    fn add_lookup(&mut self, _lookup: Lookup<Self::Variable>) {
        // Keep track of multiplicities for fixed lookups
        todo!()
    }

    fn lookup_syscall_preimage(&mut self) {
        // No-op for witness
    }

    fn lookup_syscall_hash(&mut self) {
        // No-op for witness
    }

    fn lookup_steps(&mut self) {
        // No-op for witness
    }

    fn lookup_rc16(&mut self, flag: Self::Variable, _value: Self::Variable) {
        if flag == Self::one() {
            // TODO: keep track of multiplicity of range check 16 entry
            // TODO: check that [value] is in the RangeCheck16Lookup
        }
    }

    fn lookup_reset(
        &mut self,
        flag: Self::Variable,
        _dense: Self::Variable,
        _sparse: Self::Variable,
    ) {
        if flag == Self::one() {
            // TODO: keep track of multiplicity of range check 16 entry
            // TODO: check that [dense, sparse] is in the ResetLookup
        }
    }

    fn lookup_sparse(&mut self, flag: Self::Variable, _value: Self::Variable) {
        if flag == Self::one() {
            // TODO: keep track of multiplicity of range check 16 entry
            // TODO: check that [value] is in the SparseLookup
        }
    }

    fn lookup_byte(&mut self, flag: Self::Variable, _value: Self::Variable) {
        if flag == Self::one() {
            // TODO: keep track of multiplicity of range check 16 entry
            // TODO: check that [value] is in the ByteLookup
        }
    }

    fn lookup_pad(&mut self, flag: Self::Variable, _value: Vec<Self::Variable>) {
        if flag == Self::one() {
            // TODO: keep track of multiplicity of range check 16 entry
            // TODO: check that [value] is in the PadLookup
        }
    }

    fn lookup_round_constants(&mut self, flag: Self::Variable, _value: Vec<Self::Variable>) {
        if flag == Self::one() {
            // TODO: keep track of multiplicity of range check 16 entry
            // TODO: check that [value] is in the RoundConstantsLookup
        }
    }
}
