use crate::{lookups::Lookup, E};
use ark_ff::Field;
use kimchi_msm::witness::Witness;
use std::{collections::HashMap, hash::Hash};

pub struct Circuit<const N: usize, SELECTOR, F> {
    /// The domain size of the circuit
    pub domain_size: usize,
    /// The witness for a given selector
    pub witness: HashMap<SELECTOR, Witness<N, Vec<F>>>,
    /// The vector of constraints for a given selector
    pub constraints: HashMap<SELECTOR, Vec<E<F>>>,
    /// The vector of lookups for a given selector
    pub lookups: HashMap<SELECTOR, Vec<Lookup<E<F>>>>,
}

impl<const N: usize, SELECTOR: Eq + Hash, F: Field> Circuit<N, SELECTOR, F> {
    /// Returns a boolean indicating whether the witness for the given selector is empty.
    pub fn witness_is_empty(&self, step: SELECTOR) -> bool {
        self.witness[&step].cols[0].is_empty()
    }

    /// Resets the witness after folding
    pub fn reset(&mut self, step: SELECTOR) {
        self.witness.insert(
            step,
            Witness {
                cols: Box::new(std::array::from_fn(|_| {
                    Vec::with_capacity(self.domain_size)
                })),
            },
        );
    }
}

pub trait CircuitPad<const N: usize, SELECTOR, F, Env> {
    /// Create a new circuit
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Add a witness row to the circuit
    fn push_row(&mut self, selector: SELECTOR, row: &[F; N]);

    /// Pad the rows of one selector with the given row until
    /// reaching the domain size if needed.
    /// Returns true if padding was performed, false otherwise.
    fn pad_with_row(&mut self, step: SELECTOR, row: &[F; N]) -> bool;

    /// Pads the rows of one selector with zero rows until
    /// reaching the domain size if needed.
    /// Returns true if padding was performed, false otherwise.
    fn pad_with_zeros(&mut self, step: SELECTOR) -> bool;

    /// Pad the rows of one selector with the first row until
    /// reaching the domain size if needed.
    /// Returns true if padding was performed, false otherwise.
    /// It only tries to pad witnesses which are non empty.
    fn pad_dummy(&mut self, step: SELECTOR) -> bool;

    /// Pads the rows of the witnesses until reaching the domain size using the first
    /// row repeatedly.
    fn pad_witnesses(&mut self);
}
