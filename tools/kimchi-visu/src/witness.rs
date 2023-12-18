use ark_ff::Field;
use kimchi::circuits::polynomial::KIMCHI_COLS;
use serde::Serialize;
use serde_with::serde_as;
use std::array;

/// The type that represents the execution trace.
/// It represents a table of [KIMCHI_COLS] columns, with `n` rows.
/// `n` being the maximum size of the circuit, and the size of the domain.
#[serde_as]
#[derive(Debug, Serialize)]
pub struct Witness<F>
where
    F: Field,
{
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; KIMCHI_COLS]")]
    inner: [Vec<F>; KIMCHI_COLS],
}

impl<F> Witness<F>
where
    F: Field,
{
    /// Creates a new witness with `rows` rows.
    // TODO: deprecate this
    pub fn new(rows: usize) -> Self {
        Witness {
            inner: array::from_fn(|_| vec![F::zero(); rows]),
        }
    }

    /// Returns the inner witness.
    // TODO: deprecate this
    pub fn inner(self) -> [Vec<F>; KIMCHI_COLS] {
        self.inner
    }
}

impl<F> From<[Vec<F>; KIMCHI_COLS]> for Witness<F>
where
    F: Field,
{
    fn from(inner: [Vec<F>; KIMCHI_COLS]) -> Self {
        Witness { inner }
    }
}
