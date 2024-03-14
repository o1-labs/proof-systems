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
    lookups::{FixedLookupTables, Lookup, LookupTable, LookupTableIDs::*},
};
use ark_ff::Field;
use kimchi::o1_utils::Two;
use kimchi_msm::LookupTableID;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
#[derive(Clone, Debug)]
pub struct Env<Fp> {
    /// The full state of the Keccak gate (witness)
    pub witness: KeccakWitness<Fp>,
    /// The multiplicities of each lookup entry. Should not be cleared between steps.
    pub multiplicities: Vec<Vec<u32>>,
    /// If any, an error that occurred during the execution of the constraints, to help with debugging
    pub(crate) errors: Vec<Error>,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            witness: KeccakWitness::default(),
            multiplicities: vec![
                vec![0; PadLookup.length()],
                vec![0; RoundConstantsLookup.length()],
                vec![0; ByteLookup.length()],
                vec![0; RangeCheck16Lookup.length()],
                vec![0; SparseLookup.length()],
                vec![0; ResetLookup.length()],
            ],
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

    /// Checks the constraint `tag` by checking that the input `x` is zero
    fn constrain(&mut self, tag: Constraint, x: Self::Variable) {
        if x != F::zero() {
            self.errors.push(Error::Constraint(tag));
        }
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        // Keep track of multiplicities for fixed lookups
        match lookup.table_id {
            RangeCheck16Lookup | SparseLookup | ResetLookup | RoundConstantsLookup | PadLookup
            | ByteLookup => {
                if lookup.magnitude == Self::one() {
                    // Check that the lookup value is in the table
                    if let Some(idx) = LookupTable::is_in_table(lookup.table_id, lookup.value) {
                        self.multiplicities[lookup.table_id as usize][idx] += 1;
                    } else {
                        self.errors.push(Error::Lookup(lookup.table_id));
                    }
                }
            }
            MemoryLookup | RegisterLookup | SyscallLookup | KeccakStepLookup => (),
        }
    }
}
