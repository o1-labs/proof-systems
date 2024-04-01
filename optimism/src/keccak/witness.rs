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

    ///////////////////////
    // COLUMN OPERATIONS //
    ///////////////////////

    fn is_sponge(&self) -> Self::Variable {
        Self::xor(self.is_absorb().clone(), self.is_squeeze().clone())
    }
    fn is_absorb(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Absorb))
    }
    fn is_squeeze(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Squeeze))
    }
    fn is_root(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Root))
    }
    fn is_pad(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Pad))
    }
    fn is_round(&self) -> Self::Variable {
        self.variable(KeccakColumn::Selector(Round))
    }
}
