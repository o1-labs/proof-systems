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
        column::{Absorbs::*, KeccakWitness, Sponges::*, Steps::*},
        interpreter::KeccakInterpreter,
        Constraint, Error, KeccakColumn,
        Selector::{self, *},
    },
    lookups::{FixedLookupTables, Lookup, LookupTable, LookupTableIDs::*},
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
    pub tables: Vec<LookupTable<F>>,
    /// The multiplicities of each lookup entry. Should not be cleared between steps.
    pub multiplicities: Vec<Vec<u32>>,
    /// If any, an error that occurred during the execution of the constraints, to help with debugging
    pub(crate) errors: Vec<Error>,
    /// The round number, if nonzero
    pub(crate) round: u64,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            witness: KeccakWitness::default(),
            tables: vec![
                LookupTable::table_pad(),
                LookupTable::table_round_constants(),
                LookupTable::table_byte(),
                LookupTable::table_range_check_16(),
                LookupTable::table_sparse(),
                LookupTable::table_reset(),
            ],
            multiplicities: vec![
                vec![0; PadLookup.length()],
                vec![0; RoundConstantsLookup.length()],
                vec![0; ByteLookup.length()],
                vec![0; RangeCheck16Lookup.length()],
                vec![0; SparseLookup.length()],
                vec![0; ResetLookup.length()],
            ],
            errors: vec![],
            round: 0,
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

    fn check(&mut self, tag: Selector, x: Self::Variable) {
        if x != F::zero() {
            self.errors.push(Error::Selector(tag));
        }
    }

    fn checks(&mut self) {
        // BOOLEANITY CHECKS
        {
            // Round is either true or false
            self.check(
                NotBoolean(Round(self.round)),
                Self::is_boolean(self.mode_round()),
            );
            // Absorb is either true or false
            self.check(
                NotBoolean(Sponge(Absorb(Middle))),
                Self::is_boolean(self.mode_absorb()),
            );
            // Squeeze is either true or false
            self.check(
                NotBoolean(Sponge(Squeeze)),
                Self::is_boolean(self.mode_squeeze()),
            );
            // Root is either true or false
            self.check(
                NotBoolean(Sponge(Absorb(First))),
                Self::is_boolean(self.mode_root()),
            );
            // Pad is either true or false
            self.check(
                NotBoolean(Sponge(Absorb(Last))),
                Self::is_boolean(self.mode_pad()),
            );
            // RootPad is either true or false
            self.check(
                NotBoolean(Sponge(Absorb(Only))),
                Self::is_boolean(self.mode_rootpad()),
            );
        }

        // MUTUAL EXCLUSIVITY CHECKS
        {
            // Check only one of them is one
            self.check(
                NotMutex,
                Self::is_one(
                    self.mode_round()
                        + self.mode_absorb()
                        + self.mode_squeeze()
                        + self.mode_root()
                        + self.mode_pad()
                        + self.mode_rootpad(),
                ),
            );
        }
    }

    /// Checks the constraint `tag` by checking that the input `x` is zero
    fn constrain(&mut self, tag: Constraint, if_true: Self::Variable, x: Self::Variable) {
        if if_true == Self::Variable::one() {
            if x != F::zero() {
                self.errors.push(Error::Constraint(tag));
            }
        }
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        // Keep track of multiplicities for fixed lookups
        if lookup.table_id.is_fixed() {
            // Only when reading. We ignore the other values.
            if lookup.magnitude == Self::one() {
                // Check that the lookup value is in the table
                if let Some(idx) =
                    LookupTable::is_in_table(&self.tables[lookup.table_id as usize], lookup.value)
                {
                    self.multiplicities[lookup.table_id as usize][idx] += 1;
                } else {
                    self.errors.push(Error::Lookup(lookup.table_id));
                }
            }
        }
    }

    /////////////////////////
    // SELECTOR OPERATIONS //
    /////////////////////////

    fn mode_absorb(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Sponge(Absorb(Middle))))
    }
    fn mode_squeeze(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Sponge(Squeeze)))
    }
    fn mode_root(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Sponge(Absorb(First))))
    }
    fn mode_pad(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Sponge(Absorb(Last))))
    }
    fn mode_rootpad(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Sponge(Absorb(Only))))
    }
    fn mode_round(&self) -> Self::Variable {
        // The actual round number in the selector carries no information for witness nor constraints
        // because in the witness, any usize is mapped to the same index inside the mode flags
        self.variable(KeccakColumn::Selector(Round(self.round)))
    }
}
