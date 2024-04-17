use std::collections::HashMap;

use kimchi_msm::witness::Witness;

use crate::{lookups::Lookup, E};

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

pub trait CircuitTrait<const N: usize, SELECTOR, F, Env> {
    /// Create a new circuit
    fn new(domain_size: usize, env: &mut Env) -> Self;

    /// Add a witness row to the circuit
    fn push_row(&mut self, step: SELECTOR, row: &[F; N]);

    /// Pads the rows of one selector until reaching the domain size if needed.
    /// Returns true if padding was performed, false otherwise.
    fn pad(&mut self, step: SELECTOR) -> bool;

    /// Pads the rows of the witnesses until reaching the domain size
    fn pad_witnesses(&mut self);

    /// Resets the witness after folding
    fn reset(&mut self, step: SELECTOR);
}
