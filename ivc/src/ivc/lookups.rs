// TODO Remove copy-paste. Make lookup tables composable. Remove EnumIter.
use ark_ff::{FpParameters, PrimeField};
use kimchi_msm::{
    logup::LookupTableID,
    serialization::interpreter::{LIMB_BITSIZE_SMALL, N_LIMBS_SMALL},
};
use num_bigint::BigUint;
use o1_utils::FieldHelpers;
use std::marker::PhantomData;
use strum_macros::EnumIter;

// TODO make this composable! Requires removing EnumIter

/// Enumeration of concrete lookup tables used in serialization circuit.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum IVCLookupTable<Ff> {
    /// x ∈ [0, 2^15]
    RangeCheck15,
    /// x ∈ [0, 2^4]
    RangeCheck4,
    /// x ∈ [-2^4, 2^4-1]
    RangeCheck4Abs,
    /// x ∈ [0, ff_highest] where ff_highest is the highest 15-bit
    /// limb of the modulus of the foreign field `Ff`.
    RangeCheckFfHighest(PhantomData<Ff>),
}

impl<Ff: PrimeField> LookupTableID for IVCLookupTable<Ff> {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RangeCheck4 => 2,
            Self::RangeCheck4Abs => 3,
            Self::RangeCheckFfHighest(_) => 4,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::RangeCheck15,
            2 => Self::RangeCheck4,
            3 => Self::RangeCheck4Abs,
            4 => Self::RangeCheckFfHighest(PhantomData),
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
            Self::RangeCheck4 => 1 << 4,
            Self::RangeCheck4Abs => 1 << 5,
            Self::RangeCheckFfHighest(_) => TryFrom::try_from(
                kimchi_msm::serialization::interpreter::ff_modulus_highest_limb::<Ff>(),
            )
            .unwrap(),
        }
    }

    /// Converts a value to its index in the fixed table.
    fn ix_by_value<F: PrimeField>(&self, value: F) -> usize {
        match self {
            Self::RangeCheck15 => TryFrom::try_from(value.to_biguint()).unwrap(),
            Self::RangeCheck4 => TryFrom::try_from(value.to_biguint()).unwrap(),
            Self::RangeCheck4Abs => {
                if value < F::from(1u64 << 4) {
                    TryFrom::try_from(value.to_biguint()).unwrap()
                } else {
                    TryFrom::try_from((value + F::from(2 * (1u64 << 4))).to_biguint()).unwrap()
                }
            }
            Self::RangeCheckFfHighest(_) => TryFrom::try_from(value.to_biguint()).unwrap(),
        }
    }

    fn all_variants() -> Vec<Self> {
        vec![
            Self::RangeCheck15,
            Self::RangeCheck4,
            Self::RangeCheck4Abs,
            Self::RangeCheckFfHighest(PhantomData),
        ]
    }
}

impl<Ff: PrimeField> IVCLookupTable<Ff> {
    fn entries_ff_highest<F: PrimeField>(domain_d1_size: u64) -> Vec<F> {
        let top_modulus_f = F::from_biguint(
            &kimchi_msm::serialization::interpreter::ff_modulus_highest_limb::<Ff>(),
        )
        .unwrap();
        (0..domain_d1_size)
            .map(|i| {
                if F::from(i) < top_modulus_f {
                    F::from(i)
                } else {
                    F::zero()
                }
            })
            .collect()
    }

    /// Provides a full list of entries for the given table.
    pub fn entries<F: PrimeField>(&self, domain_d1_size: u64) -> Vec<F> {
        assert!(domain_d1_size >= (1 << 15));
        match self {
            Self::RangeCheck15 => (0..domain_d1_size).map(|i| F::from(i)).collect(),
            Self::RangeCheck4 => (0..domain_d1_size)
                .map(|i| if i < (1 << 4) { F::from(i) } else { F::zero() })
                .collect(),
            Self::RangeCheck4Abs => (0..domain_d1_size)
                .map(|i| {
                    if i < (1 << 4) {
                        // [0,1,2 ... (1<<4)-1]
                        F::from(i)
                    } else if i < 2 * (1 << 4) {
                        // [-(i<<4),...-2,-1]
                        F::from(i) - F::from(2u64 * (1 << 4))
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            Self::RangeCheckFfHighest(_) => Self::entries_ff_highest::<F>(domain_d1_size),
        }
    }

    /// Checks if a value is in a given table.
    pub fn is_member<F: PrimeField>(&self, value: F) -> bool {
        match self {
            Self::RangeCheck15 => value.to_biguint() < BigUint::from(2u128.pow(15)),
            Self::RangeCheck4 => value.to_biguint() < BigUint::from(2u128.pow(4)),
            Self::RangeCheck4Abs => {
                value < F::from(1u64 << 4) || value >= F::zero() - F::from(1u64 << 4)
            }
            Self::RangeCheckFfHighest(_) => {
                let f_bui: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();
                let top_modulus_f: F =
                    F::from_biguint(&(f_bui >> ((N_LIMBS_SMALL - 1) * LIMB_BITSIZE_SMALL)))
                        .unwrap();
                value < top_modulus_f
            }
        }
    }
}
