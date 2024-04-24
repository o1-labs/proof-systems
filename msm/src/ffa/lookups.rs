use crate::logup::LookupTableID;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::FieldHelpers;
use strum_macros::EnumIter;

/// Enumeration of concrete lookup tables used in lookups circuit.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum LookupTable {
    /// x ∈ [0, 2^15]
    RangeCheck15,
    /// x ∈ [-1, 0, 1]
    RangeCheck1BitSigned,
}

impl LookupTableID for LookupTable {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RangeCheck1BitSigned => 2,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::RangeCheck15,
            2 => Self::RangeCheck1BitSigned,
            _ => panic!("Invalid lookup table id"),
        }
    }

    /// All tables are fixed tables.
    fn is_fixed(&self) -> bool {
        true
    }

    fn length(&self) -> usize {
        match self {
            Self::RangeCheck15 => 1 << 15,
            Self::RangeCheck1BitSigned => 3,
        }
    }

    /// Converts a value to its index in the fixed table.
    fn ix_by_value<F: PrimeField>(&self, value: F) -> usize {
        match self {
            Self::RangeCheck15 => TryFrom::try_from(value.to_biguint()).unwrap(),
            Self::RangeCheck1BitSigned => {
                if value == F::zero() {
                    0
                } else if value == F::one() {
                    1
                } else if value == F::zero() - F::one() {
                    2
                } else {
                    panic!("Invalid value for rangecheck1abs")
                }
            }
        }
    }
}

impl LookupTable {
    /// Provides a full list of entries for the given table.
    pub fn entries<F: PrimeField>(&self, domain_d1_size: u64) -> Vec<F> {
        assert!(domain_d1_size >= (1 << 15));
        match self {
            Self::RangeCheck1BitSigned => [F::zero(), F::one(), F::zero() - F::one()]
                .into_iter()
                .chain((3..domain_d1_size).map(|_| F::one())) // dummies are 1s
                .collect(),
            Self::RangeCheck15 => (0..domain_d1_size).map(|i| F::from(i)).collect(),
        }
    }

    /// Checks if a value is in a given table.
    pub fn is_member<F: PrimeField>(&self, value: F) -> bool {
        match self {
            Self::RangeCheck1BitSigned => {
                value == F::zero() || value == F::one() || value == F::zero() - F::one()
            }
            Self::RangeCheck15 => value.to_biguint() < BigUint::from(2u128.pow(15)),
        }
    }
}
