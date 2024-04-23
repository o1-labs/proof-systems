use crate::{lookups::Lookup, E};
use ark_ff::Zero;
use kimchi_msm::witness::Witness;
use std::{collections::HashMap, hash::Hash};

/// Struct representing a circuit execution trace containing
/// all the necessary information to generate a proof.
/// It is parameterized by
/// - COLUMNS: the number of columns (constant),
/// - SELECTOR: an enum representing the different gate behaviours,
/// - F: the type of the witness data.
pub struct Trace<const COLUMNS: usize, SELECTOR, F> {
    /// The domain size of the circuit
    pub domain_size: usize,
    /// The witness for a given selector
    pub witness: HashMap<SELECTOR, Witness<COLUMNS, Vec<F>>>,
    /// The vector of constraints for a given selector
    pub constraints: HashMap<SELECTOR, Vec<E<F>>>,
    /// The vector of lookups for a given selector
    pub lookups: HashMap<SELECTOR, Vec<Lookup<E<F>>>>,
}

impl<const COLUMNS: usize, SELECTOR: Eq + Hash, F: Zero> Trace<COLUMNS, SELECTOR, F> {
    /// Returns a boolean indicating whether the witness for the given selector was ever found in the cirucit or not.
    pub fn in_circuit(&self, opcode: SELECTOR) -> bool {
        !self.witness[&opcode].cols[0].is_empty()
    }

    /// Resets the witness after folding
    pub fn reset(&mut self, opcode: SELECTOR) {
        (self.witness.get_mut(&opcode).unwrap().cols.as_mut())
            .iter_mut()
            .for_each(Vec::clear);
    }
}

/// Tracer builds traces for some program executions.
/// The constant type `COLUMNS` is defined as the maximum number of columns/"registers" the trace can use per row.
/// The type `SELECTOR` encodes the information of the kind of information the trace encodes. Examples:
/// - For Keccak, `Step` encodes the row being performed at a time: round, squeeze, padding, etc...
/// - For MIPS, `Instruction` encodes the CPU instruction being executed: add, sub, load, store, etc...
/// The type parameter `F` is the type the data points in the trace are encoded into. It can be a field or a native type (u64).
pub trait Tracer<const COLUMNS: usize, SELECTOR, F: Zero, Env> {
    /// Create a new circuit
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Add a witness row to the circuit
    fn push_row(&mut self, opcode: SELECTOR, row: &[F; COLUMNS]);

    /// Pad the rows of one opcode with the given row until
    /// reaching the domain size if needed.
    /// Returns the number of rows that were added.
    fn pad_with_row(&mut self, opcode: SELECTOR, row: &[F; COLUMNS]) -> usize;

    /// Pads the rows of one opcode with zero rows until
    /// reaching the domain size if needed.
    /// Returns the number of rows that were added.
    fn pad_with_zeros(&mut self, opcode: SELECTOR) -> usize;

    /// Pad the rows of one opcode with the first row until
    /// reaching the domain size if needed.
    /// It only tries to pad witnesses which are non empty.
    /// Returns the number of rows that were added.
    fn pad_dummy(&mut self, opcode: SELECTOR) -> usize;

    /// Pads the rows of the witnesses until reaching the domain size using the first
    /// row repeatedly.
    fn pad_witnesses(&mut self);
}
