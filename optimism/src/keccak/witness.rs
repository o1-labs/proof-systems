//! This file contains the witness for the Keccak hash function for the zkVM project.
//! It assigns the witness values to the corresponding columns of KeccakWitness in the environment.
//!
//! The actual witness generation code makes use of the code which is already present in Kimchi,
//! to avoid code duplication and reduce error-proneness.
//!
//! For a pseudo code implementation of Keccap-f, see
//! https://keccak.team/keccak_specs_summary.html
use crate::{
    keccak::{column::KeccakWitness, interpreter::KeccakInterpreter, KeccakColumn},
    lookups::Lookup,
};
use ark_ff::Field;
use kimchi::o1_utils::Two;
