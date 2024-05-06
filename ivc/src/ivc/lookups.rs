use ark_ff::PrimeField;
use kimchi_msm::{logup::LookupTableID, serialization::lookups as serlookup};

/// Enumeration of concrete lookup tables used in serialization circuit.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum IVCLookupTable<Ff> {
    SerLookupTable(serlookup::LookupTable<Ff>),
}

impl<Ff: PrimeField> LookupTableID for IVCLookupTable<Ff> {
    fn to_u32(&self) -> u32 {
        match self {
            Self::SerLookupTable(lt) => lt.to_u32(),
        }
    }

    fn from_u32(value: u32) -> Self {
        if value < 4 {
            Self::SerLookupTable(serlookup::LookupTable::from_u32(value))
        } else {
            panic!("Invalid lookup table id")
        }
    }

    /// All tables are fixed tables.
    fn is_fixed(&self) -> bool {
        true
    }

    fn length(&self) -> usize {
        match self {
            Self::SerLookupTable(lt) => lt.length(),
        }
    }

    /// Converts a value to its index in the fixed table.
    fn ix_by_value<F: PrimeField>(&self, value: F) -> usize {
        match self {
            Self::SerLookupTable(lt) => lt.ix_by_value(value),
        }
    }

    fn all_variants() -> Vec<Self> {
        serlookup::LookupTable::<Ff>::all_variants()
            .into_iter()
            .map(IVCLookupTable::SerLookupTable)
            .collect()
    }
}
