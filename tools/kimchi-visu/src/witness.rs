use ark_ff::Field;
use array_init::array_init;
use kimchi::circuits::wires::NEW_COLS;
use serde::Serialize;
use serde_with::serde_as;

/// The type that represents the execution trace.
/// It represents a table of [NEW_COLS] columns, with `n` rows.
/// `n` being the maximum size of the circuit, and the size of the domain.
#[serde_as]
#[derive(Debug, Serialize)]
pub struct Witness<F>
where
    F: Field,
{
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; NEW_COLS]")]
    inner: [Vec<F>; NEW_COLS],
}

impl<F> Witness<F>
where
    F: Field,
{
    /// Creates a new witness with `rows` rows.
    // TODO: deprecate this
    pub fn new(rows: usize) -> Self {
        Witness {
            inner: array_init(|_| vec![F::zero(); rows]),
        }
    }

    /// Returns the inner witness.
    // TODO: deprecate this
    pub fn inner(self) -> [Vec<F>; NEW_COLS] {
        self.inner
    }
}

impl<F> From<[Vec<F>; NEW_COLS]> for Witness<F>
where
    F: Field,
{
    fn from(inner: [Vec<F>; NEW_COLS]) -> Self {
        Witness { inner }
    }
}
