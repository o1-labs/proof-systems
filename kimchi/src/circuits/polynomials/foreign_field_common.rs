//! Common parameters and functions for kimchi's foreign field circuits.

use o1_utils::{
    field_helpers::FieldHelpers,
    foreign_field::{ForeignElement, ForeignFieldHelpers},
};

use ark_ff::{Field, One, PrimeField, Zero};
use core::array;
use num_bigint::BigUint;

/// Index of low limb (in 3-limb foreign elements)
pub const LO: usize = 0;
/// Index of middle limb (in 3-limb foreign elements)
pub const MI: usize = 1;
/// Index of high limb (in 3-limb foreign elements)
pub const HI: usize = 2;

/// Limb length for foreign field elements
pub const LIMB_BITS: usize = 88;

/// Two to the power of the limb length
pub const TWO_TO_LIMB: u128 = 2u128.pow(LIMB_BITS as u32);

/// Number of desired limbs for foreign field elements
pub const LIMB_COUNT: usize = 3;

/// Exponent of binary modulus (i.e. t)
pub const BINARY_MODULUS_EXP: usize = LIMB_BITS * LIMB_COUNT;

pub type KimchiForeignElement<F> = ForeignElement<F, LIMB_BITS, LIMB_COUNT>;

/// Foreign field helpers
pub trait BigUintForeignFieldHelpers {
    /// 2
    fn two() -> Self;

    /// 2^{LIMB_BITS}
    fn two_to_limb() -> Self;

    /// 2^{2 * LIMB_BITS}
    fn two_to_2limb() -> Self;

    /// 2^t
    fn binary_modulus() -> Self;

    /// 2^259 (see foreign field multiplication RFC)
    fn max_foreign_field_modulus<F: PrimeField>() -> Self;

    /// Convert to 3 limbs of LIMB_BITS each
    fn to_limbs(&self) -> [BigUint; 3];

    /// Convert to 2 limbs of 2 * LIMB_BITS each. The compressed term is the bottom part
    fn to_compact_limbs(&self) -> [BigUint; 2];

    /// Convert to 3 PrimeField limbs of LIMB_BITS each
    fn to_field_limbs<F: Field>(&self) -> [F; 3];

    /// Convert to 2 PrimeField limbs of 2 * LIMB_BITS each. The compressed term is the bottom part.
    fn to_compact_field_limbs<F: Field>(&self) -> [F; 2];

    /// Negate: 2^T - self
    fn negate(&self) -> BigUint;
}

// @volhovm can we remove this?
// /// Two to the power of the limb length
// pub fn two_to_limb() -> BigUint {
//     BigUint::from(TWO_TO_LIMB)
// }

impl BigUintForeignFieldHelpers for BigUint {
    fn two() -> Self {
        Self::from(2u32)
    }

    fn two_to_limb() -> Self {
        BigUint::two().pow(LIMB_BITS as u32)
    }

    fn two_to_2limb() -> Self {
        BigUint::two().pow(2 * LIMB_BITS as u32)
    }

    fn binary_modulus() -> Self {
        BigUint::two().pow(3 * LIMB_BITS as u32)
    }

    fn max_foreign_field_modulus<F: PrimeField>() -> Self {
        // For simplicity and efficiency we use the approximation m = 2^259 - 1
        BigUint::two().pow(259) - BigUint::one()
    }

    fn to_limbs(&self) -> [Self; 3] {
        let mut limbs = biguint_to_limbs(self, LIMB_BITS);
        assert!(limbs.len() <= 3);
        limbs.resize(3, BigUint::zero());

        array::from_fn(|i| limbs[i].clone())
    }

    fn to_compact_limbs(&self) -> [Self; 2] {
        let mut limbs = biguint_to_limbs(self, 2 * LIMB_BITS);
        assert!(limbs.len() <= 2);
        limbs.resize(2, BigUint::zero());

        array::from_fn(|i| limbs[i].clone())
    }

    fn to_field_limbs<F: Field>(&self) -> [F; 3] {
        self.to_limbs().to_field_limbs()
    }

    fn to_compact_field_limbs<F: Field>(&self) -> [F; 2] {
        self.to_compact_limbs().to_field_limbs()
    }

    fn negate(&self) -> BigUint {
        assert!(*self < BigUint::binary_modulus());
        let neg_self = BigUint::binary_modulus() - self;
        assert_eq!(neg_self.bits(), BINARY_MODULUS_EXP as u64);
        neg_self
    }
}

/// PrimeField array BigUint helpers
pub trait FieldArrayBigUintHelpers<F: PrimeField, const N: usize> {
    /// Convert limbs from field elements to BigUint
    fn to_limbs(&self) -> [BigUint; N];

    /// Alias for to_limbs
    fn to_biguints(&self) -> [BigUint; N] {
        self.to_limbs()
    }
}

impl<F: PrimeField, const N: usize> FieldArrayBigUintHelpers<F, N> for [F; N] {
    fn to_limbs(&self) -> [BigUint; N] {
        array::from_fn(|i| self[i].to_biguint())
    }
}

/// PrimeField array compose BigUint
pub trait FieldArrayCompose<F: PrimeField, const N: usize> {
    /// Compose field limbs into BigUint
    fn compose(&self) -> BigUint;
}

impl<F: PrimeField> FieldArrayCompose<F, 2> for [F; 2] {
    fn compose(&self) -> BigUint {
        fields_compose(self, &BigUint::two_to_2limb())
    }
}

impl<F: PrimeField> FieldArrayCompose<F, 3> for [F; 3] {
    fn compose(&self) -> BigUint {
        fields_compose(self, &BigUint::two_to_limb())
    }
}

/// PrimeField array compact limbs
pub trait FieldArrayCompact<F: PrimeField> {
    /// Compose field limbs into BigUint
    fn to_compact_limbs(&self) -> [F; 2];
}

impl<F: PrimeField> FieldArrayCompact<F> for [F; 3] {
    fn to_compact_limbs(&self) -> [F; 2] {
        [
            self[0] + KimchiForeignElement::<F>::two_to_limb() * self[1],
            self[2],
        ]
    }
}

/// BigUint array PrimeField helpers
pub trait BigUintArrayFieldHelpers<const N: usize> {
    /// Convert limbs from BigUint to field element
    fn to_field_limbs<F: Field>(&self) -> [F; N];

    /// Alias for to_field_limbs
    fn to_fields<F: Field>(&self) -> [F; N] {
        self.to_field_limbs()
    }
}

impl<const N: usize> BigUintArrayFieldHelpers<N> for [BigUint; N] {
    fn to_field_limbs<F: Field>(&self) -> [F; N] {
        biguints_to_fields(self)
    }
}

/// BigUint array compose helper
pub trait BigUintArrayCompose<const N: usize> {
    /// Compose limbs into BigUint
    fn compose(&self) -> BigUint;
}

impl BigUintArrayCompose<2> for [BigUint; 2] {
    fn compose(&self) -> BigUint {
        bigunits_compose(self, &BigUint::two_to_2limb())
    }
}

impl BigUintArrayCompose<3> for [BigUint; 3] {
    fn compose(&self) -> BigUint {
        bigunits_compose(self, &BigUint::two_to_limb())
    }
}

// Compose field limbs into BigUint value
fn fields_compose<F: PrimeField, const N: usize>(limbs: &[F; N], base: &BigUint) -> BigUint {
    limbs
        .iter()
        .cloned()
        .enumerate()
        .fold(BigUint::zero(), |x, (i, limb)| {
            x + base.pow(i as u32) * limb.to_biguint()
        })
}

// Convert array of BigUint to an array of PrimeField
fn biguints_to_fields<F: Field, const N: usize>(limbs: &[BigUint; N]) -> [F; N] {
    array::from_fn(|i| {
        F::from_random_bytes(&limbs[i].to_bytes_le())
            .expect("failed to convert BigUint to field element")
    })
}

// Compose limbs into BigUint value
fn bigunits_compose<const N: usize>(limbs: &[BigUint; N], base: &BigUint) -> BigUint {
    limbs
        .iter()
        .cloned()
        .enumerate()
        .fold(BigUint::zero(), |x, (i, limb)| {
            x + base.pow(i as u32) * limb
        })
}

// Split a BigUint up into limbs of size limb_size (in little-endian order)
fn biguint_to_limbs(x: &BigUint, limb_bits: usize) -> Vec<BigUint> {
    let bytes = x.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes.chunks(limb_bits / 8).collect();
    chunks
        .iter()
        .map(|chunk| BigUint::from_bytes_le(chunk))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::AffineRepr;
    use ark_ff::One;
    use mina_curves::pasta::Pallas as CurvePoint;
    use num_bigint::RandBigInt;

    /// Base field element type
    pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

    fn secp256k1_modulus() -> BigUint {
        BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
    }

    #[test]
    fn test_negate_modulus_safe1() {
        secp256k1_modulus().negate();
    }

    #[test]
    fn test_negate_modulus_safe2() {
        BigUint::binary_modulus().sqrt().negate();
    }

    #[test]
    fn test_negate_modulus_safe3() {
        (BigUint::binary_modulus() / BigUint::from(2u32)).negate();
    }

    #[test]
    #[should_panic]
    fn test_negate_modulus_unsafe1() {
        (BigUint::binary_modulus() - BigUint::one()).negate();
    }

    #[test]
    #[should_panic]
    fn test_negate_modulus_unsafe2() {
        (BigUint::binary_modulus() + BigUint::one()).negate();
    }

    #[test]
    #[should_panic]
    fn test_negate_modulus_unsafe3() {
        BigUint::binary_modulus().negate();
    }

    #[test]
    fn check_negation() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        for _ in 0..10 {
            rng.gen_biguint(256).negate();
        }
    }

    #[test]
    fn check_good_limbs() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        for _ in 0..100 {
            let x = rng.gen_biguint(264);
            assert_eq!(x.to_limbs().len(), 3);
            assert_eq!(x.to_limbs().compose(), x);
            assert_eq!(x.to_compact_limbs().len(), 2);
            assert_eq!(x.to_compact_limbs().compose(), x);
            assert_eq!(x.to_compact_limbs().compose(), x.to_limbs().compose());

            assert_eq!(x.to_field_limbs::<BaseField>().len(), 3);
            assert_eq!(x.to_field_limbs::<BaseField>().compose(), x);
            assert_eq!(x.to_compact_field_limbs::<BaseField>().len(), 2);
            assert_eq!(x.to_compact_field_limbs::<BaseField>().compose(), x);
            assert_eq!(
                x.to_compact_field_limbs::<BaseField>().compose(),
                x.to_field_limbs::<BaseField>().compose()
            );

            assert_eq!(x.to_limbs().to_fields::<BaseField>(), x.to_field_limbs());
            assert_eq!(x.to_field_limbs::<BaseField>().to_biguints(), x.to_limbs());
        }
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_1() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        assert_ne!(rng.gen_biguint(265).to_limbs().len(), 3);
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_2() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        assert_ne!(rng.gen_biguint(265).to_compact_limbs().len(), 2);
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_3() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        assert_ne!(rng.gen_biguint(265).to_field_limbs::<BaseField>().len(), 3);
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_4() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        assert_ne!(
            rng.gen_biguint(265)
                .to_compact_field_limbs::<BaseField>()
                .len(),
            2
        );
    }
}
