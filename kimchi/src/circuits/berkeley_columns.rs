use crate::circuits::{gate::GateType, lookup::lookups::LookupPattern};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// A type representing one of the polynomials involved in the PLONK IOP.
pub enum Column {
    Witness(usize),
    Z,
    LookupSorted(usize),
    LookupAggreg,
    LookupTable,
    LookupKindIndex(LookupPattern),
    LookupRuntimeSelector,
    LookupRuntimeTable,
    Index(GateType),
    Coefficient(usize),
    Permutation(usize),
}
