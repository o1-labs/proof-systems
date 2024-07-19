use crate::{logup::LookupTableID, Logup, LIMB_BITSIZE, N_LIMBS};
use ark_ff::{FpParameters, PrimeField};
use num_bigint::BigUint;
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
    /// x ∈ [-2^14, 2^14-1]
    RangeCheck14Abs,
    /// x ∈ [-2^4, 2^4-1]
    RangeCheck9Abs,
    /// x ∈ [0, ff_highest] where ff_highest is the highest 15-bit
    /// limb of the modulus of the foreign field `Ff`.
    RangeCheckFfHighest(PhantomData<Ff>),
    /// Communication bus for the multiplication circuit.
    MultiplicationBus,
}

impl<Ff: PrimeField> LookupTableID for LookupTable<Ff> {
    fn to_u32(&self) -> u32 {
        match self {
            Self::RangeCheck15 => 1,
            Self::RangeCheck4 => 2,
            Self::RangeCheck14Abs => 3,
            Self::RangeCheck9Abs => 4,
            Self::RangeCheckFfHighest(_) => 5,
            Self::MultiplicationBus => 6,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::RangeCheck15,
            2 => Self::RangeCheck4,
            3 => Self::RangeCheck14Abs,
            4 => Self::RangeCheck9Abs,
            5 => Self::RangeCheckFfHighest(PhantomData),
            6 => Self::MultiplicationBus,
            _ => panic!("Invalid lookup table id"),
        }
    }

    /// All tables are fixed tables.
    fn is_fixed(&self) -> bool {
        match self {
            Self::RangeCheck15 => true,
            Self::RangeCheck4 => true,
            Self::RangeCheck14Abs => true,
            Self::RangeCheck9Abs => true,
            Self::RangeCheckFfHighest(_) => true,
            Self::MultiplicationBus => false,
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::RangeCheck15 => 1 << 15,
            Self::RangeCheck4 => 1 << 4,
            Self::RangeCheck14Abs => 1 << 15,
            Self::RangeCheck9Abs => 1 << 10,
            Self::RangeCheckFfHighest(_) => TryFrom::try_from(
                crate::serialization::interpreter::ff_modulus_highest_limb::<Ff>(),
            )
            .unwrap(),
            Self::MultiplicationBus => 1 << 15,
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
            Self::RangeCheck4 => Some(TryFrom::try_from(value.to_biguint()).unwrap()),
            Self::RangeCheck14Abs => {
                if value < F::from(1u64 << 14) {
                    Some(TryFrom::try_from(value.to_biguint()).unwrap())
                } else {
                    Some(
                        TryFrom::try_from((value + F::from(2 * (1u64 << 14))).to_biguint())
                            .unwrap(),
                    )
                }
            }
            Self::RangeCheck9Abs => {
                if value < F::from(1u64 << 9) {
                    Some(TryFrom::try_from(value.to_biguint()).unwrap())
                } else {
                    Some(
                        TryFrom::try_from((value + F::from(2 * (1u64 << 9))).to_biguint()).unwrap(),
                    )
                }
            }

            Self::RangeCheckFfHighest(_) => Some(TryFrom::try_from(value.to_biguint()).unwrap()),
            Self::MultiplicationBus => None,
        }
    }

    fn all_variants() -> Vec<Self> {
        vec![
            Self::RangeCheck15,
            Self::RangeCheck14Abs,
            Self::RangeCheck9Abs,
            Self::RangeCheck4,
            Self::RangeCheckFfHighest(PhantomData),
            Self::MultiplicationBus,
        ]
    }
}

impl<Ff: PrimeField> LookupTable<Ff> {
    fn entries_ff_highest<F: PrimeField>(domain_d1_size: u64) -> Vec<F> {
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

    /// Provides a full list of entries for the given table.
    pub fn entries<F: PrimeField>(&self, domain_d1_size: u64) -> Option<Vec<F>> {
        assert!(domain_d1_size >= (1 << 15));
        match self {
            Self::RangeCheck15 => Some((0..domain_d1_size).map(|i| F::from(i)).collect()),
            Self::RangeCheck4 => Some(
                (0..domain_d1_size)
                    .map(|i| if i < (1 << 4) { F::from(i) } else { F::zero() })
                    .collect(),
            ),
            Self::RangeCheck14Abs => Some(
                (0..domain_d1_size)
                    .map(|i| {
                        if i < (1 << 14) {
                            // [0,1,2 ... (1<<14)-1]
                            F::from(i)
                        } else if i < 2 * (1 << 14) {
                            // [-(i<<14),...-2,-1]
                            F::from(i) - F::from(2u64 * (1 << 14))
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
            ),

            Self::RangeCheck9Abs => Some(
                (0..domain_d1_size)
                    .map(|i| {
                        if i < (1 << 9) {
                            // [0,1,2 ... (1<<9)-1]
                            F::from(i)
                        } else if i < 2 * (1 << 9) {
                            // [-(i<<9),...-2,-1]
                            F::from(i) - F::from(2u64 * (1 << 9))
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
            ),
            Self::RangeCheckFfHighest(_) => Some(Self::entries_ff_highest::<F>(domain_d1_size)),
            _ => panic!("not possible"),
        }
    }

    /// Checks if a value is in a given table.
    pub fn is_member<F: PrimeField>(&self, value: F) -> Option<bool> {
        match self {
            Self::RangeCheck15 => Some(value.to_biguint() < BigUint::from(2u128.pow(15))),
            Self::RangeCheck4 => Some(value.to_biguint() < BigUint::from(2u128.pow(4))),
            Self::RangeCheck14Abs => {
                Some(value < F::from(1u64 << 14) || value >= F::zero() - F::from(1u64 << 14))
            }
            Self::RangeCheck9Abs => {
                Some(value < F::from(1u64 << 9) || value >= F::zero() - F::from(1u64 << 9))
            }
            Self::RangeCheckFfHighest(_) => {
                let f_bui: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();
                let top_modulus_f: F =
                    F::from_biguint(&(f_bui >> ((N_LIMBS - 1) * LIMB_BITSIZE))).unwrap();
                Some(value < top_modulus_f)
            }
            Self::MultiplicationBus => None,
        }
    }
}

pub type Lookup<F, Ff> = Logup<F, LookupTable<Ff>>;
