//! This file contains the witness for the Keccak hash function for the zkVM project.
//! It assigns the witness values to the corresponding columns of KeccakWitness in the environment.
//!
//! The actual witness generation code makes use of the code which is already present in Kimchi,
//! to avoid code duplication and reduce error-proneness.
//!
//! For a pseudo code implementation of Keccap-f, see
//! <https://keccak.team/keccak_specs_summary.html>
use std::collections::HashMap;

use crate::{
    interpreters::keccak::{
        column::KeccakWitness,
        helpers::{ArithHelpers, BoolHelpers, LogupHelpers},
        interpreter::{Interpreter, KeccakInterpreter},
        Constraint, Error, KeccakColumn,
    },
    lookups::{
        FixedLookupTables, Lookup, LookupTable,
        LookupTableIDs::{self, *},
    },
};

use ark_ff::Field;
use kimchi::o1_utils::Two;
use kimchi_msm::LookupTableID;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
// TODO: the fixed tables information should be inferred from the general environment
#[derive(Clone, Debug)]
pub struct Env<F> {
    /// The full state of the Keccak gate (witness)
    pub witness: KeccakWitness<F>,
    /// The fixed tables used in the Keccak gate
    pub tables: HashMap<LookupTableIDs, LookupTable<F>>,
    /// The multiplicities of each lookup entry. Should not be cleared between steps.
    pub multiplicities: HashMap<LookupTableIDs, Vec<u32>>,
    /// If any, an error that occurred during the execution of the constraints, to help with debugging
    pub(crate) errors: Vec<Error>,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            witness: KeccakWitness::default(),
            tables: {
                let mut t = HashMap::new();
                t.insert(PadLookup, LookupTable::table_pad());
                t.insert(RoundConstantsLookup, LookupTable::table_round_constants());
                t.insert(AtMost4Lookup, LookupTable::table_at_most_4());
                t.insert(ByteLookup, LookupTable::table_byte());
                t.insert(RangeCheck16Lookup, LookupTable::table_range_check_16());
                t.insert(SparseLookup, LookupTable::table_sparse());
                t.insert(ResetLookup, LookupTable::table_reset());
                t
            },
            multiplicities: {
                let mut m = HashMap::new();
                m.insert(PadLookup, vec![0; PadLookup.length()]);
                m.insert(RoundConstantsLookup, vec![0; RoundConstantsLookup.length()]);
                m.insert(AtMost4Lookup, vec![0; AtMost4Lookup.length()]);
                m.insert(ByteLookup, vec![0; ByteLookup.length()]);
                m.insert(RangeCheck16Lookup, vec![0; RangeCheck16Lookup.length()]);
                m.insert(SparseLookup, vec![0; SparseLookup.length()]);
                m.insert(ResetLookup, vec![0; ResetLookup.length()]);
                m
            },
            errors: vec![],
        }
    }
}

impl<F: Field> ArithHelpers<F> for Env<F> {
    fn two_pow(x: u64) -> <Env<F> as Interpreter<F>>::Variable {
        Self::constant_field(F::two_pow(x))
    }
}

impl<F: Field> BoolHelpers<F> for Env<F> {}

impl<F: Field> LogupHelpers<F> for Env<F> {}

impl<F: Field> Interpreter<F> for Env<F> {
    type Variable = F;

    fn constant(x: u64) -> Self::Variable {
        Self::constant_field(F::from(x))
    }

    fn constant_field(x: F) -> Self::Variable {
        x
    }

    fn variable(&self, column: KeccakColumn) -> Self::Variable {
        self.witness[column]
    }

    /// Checks the constraint `tag` by checking that the input `x` is zero
    fn constrain(&mut self, tag: Constraint, if_true: Self::Variable, x: Self::Variable) {
        if if_true == Self::Variable::one() && x != F::zero() {
            self.errors.push(Error::Constraint(tag));
        }
    }

    fn add_lookup(&mut self, if_true: Self::Variable, lookup: Lookup<Self::Variable>) {
        // Keep track of multiplicities for fixed lookups
        if if_true == Self::Variable::one() && lookup.table_id.is_fixed() {
            // Only when reading. We ignore the other values.
            if lookup.magnitude == Self::one() {
                // Check that the lookup value is in the table
                if let Some(idx) = LookupTable::is_in_table(
                    self.tables.get_mut(&lookup.table_id).unwrap(),
                    lookup.value,
                ) {
                    self.multiplicities.get_mut(&lookup.table_id).unwrap()[idx] += 1;
                } else {
                    self.errors.push(Error::Lookup(lookup.table_id));
                }
            }
        }
    }
}

impl<F: Field> KeccakInterpreter<F> for Env<F> {}
