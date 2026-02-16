use crate::logup::LookupTableID;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::FieldHelpers;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum LookupTable {
    /// Fixed table, x ∈ [0, 2^15].
    RangeCheck15,
    /// A runtime table, with no explicit writes.
    RuntimeTable1,
    /// A runtime table, with explicit writes.
    RuntimeTable2,
}

impl LookupTableID for LookupTable {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RuntimeTable1 => 2,
            Self::RuntimeTable2 => 3,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::RangeCheck15,
            2 => Self::RuntimeTable1,
            3 => Self::RuntimeTable2,
            _ => panic!("Invalid lookup table id"),
        }
    }

    fn is_fixed(&self) -> bool {
        match self {
            Self::RangeCheck15 => true,
            Self::RuntimeTable1 => false,
            Self::RuntimeTable2 => false,
        }
    }

    fn runtime_create_column(&self) -> bool {
        match self {
            Self::RuntimeTable1 => true,
            Self::RuntimeTable2 => false,
            _ => panic!("runtime_create_column was called on a non-runtime table"),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::RangeCheck15 => 1 << 15,
            Self::RuntimeTable1 => 1 << 15,
            Self::RuntimeTable2 => 1 << 15,
        }
    }

    /// Converts a value to its index in the fixed table.
    fn ix_by_value<F: PrimeField>(&self, value: &[F]) -> Option<usize> {
        let value = value[0];
        if self.is_fixed() {
            assert!(self.is_member(value).unwrap());
        }

        match self {
            Self::RangeCheck15 => Some(TryFrom::try_from(value.to_biguint()).unwrap()),
            Self::RuntimeTable1 => None,
            Self::RuntimeTable2 => None,
        }
    }

    fn all_variants() -> Vec<Self> {
        vec![Self::RangeCheck15, Self::RuntimeTable1, Self::RuntimeTable2]
    }
}

impl LookupTable {
    /// Provides a full list of entries for the given table.
    pub fn entries<F: PrimeField>(&self, domain_d1_size: u64) -> Option<Vec<F>> {
        assert!(domain_d1_size >= (1 << 15));
        match self {
            Self::RangeCheck15 => Some((0..domain_d1_size).map(|i| F::from(i)).collect()),
            _ => panic!("not possible"),
        }
    }

    /// Checks if a value is in a given table.
    pub fn is_member<F: PrimeField>(&self, value: F) -> Option<bool> {
        match self {
            Self::RangeCheck15 => Some(value.to_biguint() < BigUint::from(2u128.pow(15))),
            Self::RuntimeTable1 => None,
            Self::RuntimeTable2 => None,
        }
    }
}
