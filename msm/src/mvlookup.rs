//! Implement the protocol MVLookup https://eprint.iacr.org/2022/1530.pdf

#[derive(Copy, Clone, Debug)]
pub enum LookupTable {
    RangeCheck16 = 1,
}

pub struct Lookup<F> {
    pub(crate) table_id: LookupTable,
    pub(crate) numerator: F,
    pub(crate) value: Vec<F>,
}

/// Represents a witness of one instance of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - `Vec<Lookup<F: Field>>` for the evaluations
/// - Polycomm<G: KimchiCurve> for the commitments
/// TODO: Use this instead of lookup_counters and lookups in prove
pub struct LookupWitness<T> {
    /// A list of functions/looked-up values.
    pub(crate) f: Vec<T>,
    /// The table the lookup is performed on.
    pub(crate) t: T,
    /// The multiplicity polynomial
    pub(crate) m: T,
}

/// Represents the proof of the lookup argument
/// It is parametrized by the type `T` which can be either:
/// - Polycomm<G: KimchiCurve> for the commitments
/// - (F, F) for the evaluations at zeta and zeta omega.
#[derive(Debug)]
pub struct LookupProof<T> {
    pub(crate) m: T,
    // Contain t. FIXME
    pub(crate) f: Vec<T>,
    // pub(crate) t: T,
    pub(crate) sum: T,
}
