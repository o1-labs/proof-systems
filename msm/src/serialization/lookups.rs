use crate::{logup::LookupTableID, Logup};
use ark_ff::PrimeField;
use o1_utils::FieldHelpers;
use std::marker::PhantomData;
use strum_macros::EnumIter;

/// Enumeration of concrete lookup tables used in serialization circuit.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum LookupTable<Ff> {
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

impl<Ff: PrimeField> LookupTableID for LookupTable<Ff> {
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
                crate::serialization::interpreter::ff_modulus_highest_limb::<Ff>(),
            )
            .unwrap(),
        }
    }
}

impl<Ff: PrimeField> LookupTable<Ff> {
    pub fn entries_ff_highest<F: PrimeField>(domain_d1_size: u64) -> Vec<F> {
        let top_modulus_f =
            F::from_biguint(&crate::serialization::interpreter::ff_modulus_highest_limb::<Ff>())
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
}

impl<Ff: PrimeField> LookupTable<Ff> {}

pub type Lookup<F, Ff> = Logup<F, LookupTable<Ff>>;
