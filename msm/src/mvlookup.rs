/// Implement the protocol MVLookup https://eprint.iacr.org/2022/1530.pdf
use ark_ff::Field;

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
/// The type is parametrized by the type `T` which can be either:
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
