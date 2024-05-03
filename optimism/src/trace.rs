use crate::{lookups::Lookup, E};
use ark_ff::{One, Zero};
use kimchi_msm::witness::Witness;
use std::{collections::BTreeMap, hash::Hash};

/// Returns the index of the witness column in the trace.
pub trait Indexer {
    fn ix(&self) -> usize;
}

/// Struct representing a circuit execution trace containing
/// all the necessary information to generate a proof.
/// It is parameterized by
/// - N: the total number of columns (constant), it must equal N_REL + N_SEL
/// - N_REL: the number of relation columns (constant),
/// - N_SEL: the number of selector columns (constant),
/// - Selector: an enum representing the different gate behaviours,
/// - F: the type of the witness data.
pub struct Trace<const N: usize, const N_REL: usize, const N_SEL: usize, Selector, F> {
    /// The domain size of the circuit
    pub domain_size: usize,
    /// The witness for a given selector
    /// - the last N_SEL columns represent the selector columns
    ///   and only the one for `Selector` should be all ones (the rest of selector columns should be all zeros)
    pub witness: BTreeMap<Selector, Witness<N, Vec<F>>>,
    /// The vector of constraints for a given selector
    pub constraints: BTreeMap<Selector, Vec<E<F>>>,
    /// The vector of lookups for a given selector
    pub lookups: BTreeMap<Selector, Vec<Lookup<E<F>>>>,
}

impl<
        const N: usize,
        const N_REL: usize,
        const N_SEL: usize,
        Selector: Eq + Hash + Indexer + Copy + Ord + PartialOrd,
        F: Zero + One,
    > Trace<N, N_REL, N_SEL, Selector, F>
{
    /// Returns the number of rows that have been instantiated for the given selector.
    /// It is important that the column used is a relation column because selector columns
    /// are only instantiated at the very end, so their length could be zero most times.
    pub fn number_of_rows(&self, opcode: Selector) -> usize {
        self.witness[&opcode].cols[0].len()
    }

    /// Returns a boolean indicating whether the witness for the given selector was ever found in the cirucit or not.
    pub fn in_circuit(&self, opcode: Selector) -> bool {
        self.number_of_rows(opcode) != 0
    }

    /// Returns whether the witness for the given selector has achieved a number of rows that is equal to the domain size.
    pub fn is_full(&self, opcode: Selector) -> bool {
        self.domain_size == self.number_of_rows(opcode)
    }

    /// Resets the witness after folding
    pub fn reset(&mut self, opcode: Selector) {
        (self.witness.get_mut(&opcode).unwrap().cols.as_mut())
            .iter_mut()
            .for_each(Vec::clear);
    }

    /// Sets the selector column to all ones, and the rest to all zeros
    pub fn set_selector_column(&mut self, selector: Selector, number_of_rows: usize) {
        (N_REL..N).for_each(|i| {
            if i == selector.ix() {
                self.witness.get_mut(&selector).unwrap().cols[i]
                    .extend((0..number_of_rows).map(|_| F::one()))
            } else {
                self.witness.get_mut(&selector).unwrap().cols[i]
                    .extend((0..number_of_rows).map(|_| F::zero()))
            }
        });
    }
}

/// Tracer builds traces for some program executions.
/// The constant type `N` is defined as the maximum number of columns the trace can use per row.
/// The constant type `N_REL` is defined as the maximum number of relation columns the trace can use per row.
/// The constant type `N_SEL` is defined as the number of selector columns the trace can use per row.
/// The type `Selector` encodes the information of the kind of information the trace encodes. Examples:
/// - For Keccak, `Step` encodes the row being performed at a time: round, squeeze, padding, etc...
/// - For MIPS, `Instruction` encodes the CPU instruction being executed: add, sub, load, store, etc...
/// The type parameter `F` is the type the data points in the trace are encoded into. It can be a field or a native type (u64).
pub trait Tracer<const N: usize, const N_REL: usize, const N_SEL: usize, Selector, F: Zero, Env> {
    /// Create a new circuit
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Add a witness row to the circuit (only for relation columns)
    fn push_row(&mut self, opcode: Selector, row: &[F; N_REL]);

    /// Pad the rows of one opcode with the given row until
    /// reaching the domain size if needed.
    /// Returns the number of rows that were added.
    /// It does not add selector columns.
    fn pad_with_row(&mut self, opcode: Selector, row: &[F; N_REL]) -> usize;

    /// Pads the rows of one opcode with zero rows until
    /// reaching the domain size if needed.
    /// Returns the number of rows that were added.
    /// It does not add selector columns.
    fn pad_with_zeros(&mut self, opcode: Selector) -> usize;

    /// Pad the rows of one opcode with the first row until
    /// reaching the domain size if needed.
    /// It only tries to pad witnesses which are non empty.
    /// Returns the number of rows that were added.
    /// It does not add selector columns.
    fn pad_dummy(&mut self, opcode: Selector) -> usize;

    /// Pads the rows of the witnesses until reaching the domain size using the first
    /// row repeatedly. It does not add selector columns.
    fn pad_witnesses(&mut self);
}
