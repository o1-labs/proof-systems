use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::composition::MPrism, fec::lookups as feclookup, logup::LookupTableID,
    serialization::lookups as serlookup,
};
use std::marker::PhantomData;

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

pub struct IVCFECLookupLens<Ff>(pub PhantomData<Ff>);

impl<Ff> MPrism for IVCFECLookupLens<Ff> {
    type Source = IVCLookupTable<Ff>;
    type Target = feclookup::LookupTable<Ff>;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck15) => {
                Some(feclookup::LookupTable::RangeCheck15)
            }
            IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck14Abs) => {
                Some(feclookup::LookupTable::RangeCheck14Abs)
            }
            IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck9Abs) => {
                Some(feclookup::LookupTable::RangeCheck9Abs)
            }
            IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheckFfHighest(p)) => {
                Some(feclookup::LookupTable::RangeCheckFfHighest(p))
            }
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        match target {
            feclookup::LookupTable::RangeCheck15 => {
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck15)
            }
            feclookup::LookupTable::RangeCheck14Abs => {
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck14Abs)
            }
            feclookup::LookupTable::RangeCheck9Abs => {
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck9Abs)
            }
            feclookup::LookupTable::RangeCheckFfHighest(p) => {
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheckFfHighest(p))
            }
        }
    }
}
