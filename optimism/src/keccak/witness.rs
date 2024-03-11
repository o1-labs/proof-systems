//! This file contains the witness for the Keccak hash function for the zkVM project.
//! It assigns the witness values to the corresponding columns of KeccakWitness in the environment.
//!
//! The actual witness generation code makes use of the code which is already present in Kimchi,
//! to avoid code duplication and reduce error-proneness.
//!
//! For a pseudo code implementation of Keccap-f, see
//! <https://keccak.team/keccak_specs_summary.html>
use crate::keccak::{column::KeccakWitness, interpreter::KeccakInterpreter, KeccakColumn};
use ark_ff::Field;
use kimchi::o1_utils::Two;

/// This struct contains all that needs to be kept track of during the execution of the Keccak step interpreter
#[derive(Clone, Debug)]
pub struct Env<Fp> {
    /// The full state of the Keccak gate (witness)
    pub witness: KeccakWitness<Fp>,
    // The multiplicities of each lookup table
    // TODO
    /// A counter of constraints to help with debugging, starts with 1
    pub(crate) check_idx: usize,
}

impl<F: Field> Default for Env<F> {
    fn default() -> Self {
        Self {
            witness: KeccakWitness::default(),
            check_idx: 0,
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
    fn constrain(&mut self, x: Self::Variable) {
        self.check_idx += 1;
        assert_eq!(
            x,
            F::zero(),
            "Keccak witness failed at constraint index {}",
            self.check_idx
        );
    }
}
