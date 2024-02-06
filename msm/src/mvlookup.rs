//! Implement the protocol MVLookup https://eprint.iacr.org/2022/1530.pdf

// TODO: Add more built-in lookup tables
#[derive(Copy, Clone, Debug)]
pub enum LookupTable {
    RangeCheck16 = 1,
}

/// Generic structure to represent a (vector) lookup the table with ID
/// `table_id`.
/// The table ID is added to the random linear combination formed with the
/// values. The combiner for the random linear combination is coined during the
/// proving phase by the prover.
pub struct Lookup<F> {
    #[allow(dead_code)]
    pub(crate) table_id: LookupTable,
    #[allow(dead_code)]
    pub(crate) numerator: F,
    #[allow(dead_code)]
    pub(crate) value: Vec<F>,
}

/// Represents a witness of one instance of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - `Vec<Lookup<F: Field>>` for the evaluations
/// - Polycomm<G: KimchiCurve> for the commitments
pub struct LookupWitness<T> {
    /// A list of functions/looked-up values.
    #[allow(dead_code)]
    pub(crate) f: Vec<T>,
    /// The table the lookup is performed on.
    #[allow(dead_code)]
    pub(crate) t: T,
    /// The multiplicity polynomial
    #[allow(dead_code)]
    pub(crate) m: T,
}

/// Represents the proof of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - Polycomm<G: KimchiCurve> for the commitments
/// - (F, F) for the evaluations at zeta and zeta omega.
#[derive(Debug)]
pub struct LookupProof<T> {
    #[allow(dead_code)]
    pub(crate) m: T,
    // FIXME: split t and f
    // Contain t.
    #[allow(dead_code)]
    pub(crate) f: Vec<T>,
    // pub(crate) t: T,
    #[allow(dead_code)]
    pub(crate) sum: T,
}
