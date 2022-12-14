//! Describes helpers for foreign field arithmetics

use crate::field_helpers::FieldHelpers;
use crate::Two;
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use num_traits::Zero;
use std::array;
use std::fmt::{Debug, Formatter};
use std::ops::{Index, IndexMut};

/// Index of low limb (in 3-limb foreign elements)
pub const LO: usize = 0;
/// Index of middle limb (in 3-limb foreign elements)
pub const MI: usize = 1;
/// Index of high limb (in 3-limb foreign elements)
pub const HI: usize = 2;

/// Limb length for foreign field elements
pub const LIMB_BITS: usize = 88;

/// Number of desired limbs for foreign field elements
pub const LIMB_COUNT: usize = 3;

/// Exponent of binary modulus (i.e. t)
pub const BINARY_MODULUS_EXP: usize = LIMB_BITS * LIMB_COUNT;

/// Represents a foreign field element
#[derive(Clone, PartialEq, Eq)]
/// Represents a foreign field element
pub struct ForeignElement<F: Field, const N: usize> {
    /// limbs in little endian order
    pub limbs: [F; N],
    /// number of limbs used for the foreign field element
    len: usize,
}

impl<F: Field, const N: usize> ForeignElement<F, N> {
    /// Creates a new foreign element from an array containing N limbs
    pub fn new(limbs: [F; N]) -> Self {
        Self { limbs, len: N }
    }

    /// Creates a new foreign element representing the value zero
    pub fn zero() -> Self {
        Self {
            limbs: [F::zero(); N],
            len: N,
        }
    }

    /// Initializes a new foreign element from a big unsigned integer
    /// Panics if the BigUint is too large to fit in the `N` limbs
    pub fn from_biguint(big: BigUint) -> Self {
        let vec = ForeignElement::<F, N>::big_to_vec(big);

        // create an array of N native elements containing the limbs
        // until the array is full in big endian, so most significant
        // limbs may be zero if the big number is smaller
        if vec.len() > N {
            panic!("BigUint element is too large for N limbs");
        }

        let mut limbs = [F::zero(); N];
        for (i, term) in vec.iter().enumerate() {
            limbs[i] = *term;
        }

        Self {
            limbs,
            len: limbs.len(),
        }
    }

    /// Initializes a new foreign element from an absolute `BigUint` but the equivalent
    /// foreign element obtained corresponds to the negated input. It first converts the
    /// input big element to a big integer modulo the foreign field modulus, and then
    /// computes the negation of the result.
    pub fn neg(&self, modulus: &BigUint) -> Self {
        let big = self.to_biguint();
        let ok = big % modulus;
        let neg = modulus - ok;
        Self::from_biguint(neg)
    }

    /// Initializes a new foreign element from a set of bytes in big endian
    pub fn from_be(bytes: &[u8]) -> Self {
        Self::from_biguint(BigUint::from_bytes_be(bytes))
    }

    /// Obtains the big integer representation of the foreign field element
    pub fn to_biguint(&self) -> BigUint {
        let mut bytes = vec![];
        // limbs are stored in little endian
        for limb in self.limbs {
            let crumb = &limb.to_bytes()[0..LIMB_BITS / 8];
            bytes.extend_from_slice(crumb);
        }
        BigUint::from_bytes_le(&bytes)
    }

    /// Split a foreign field element into a vector of `LIMB_BITS` bits field elements of type `F` in little-endian.
    /// Right now it is written so that it gives `LIMB_COUNT` limbs, even if it fits in less bits.
    fn big_to_vec(fe: BigUint) -> Vec<F> {
        let bytes = fe.to_bytes_le();
        let chunks: Vec<&[u8]> = bytes.chunks(LIMB_BITS / 8).collect();
        chunks
            .iter()
            .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
            .collect()
    }
}

impl<F: PrimeField, const N: usize> ForeignElement<F, N> {
    /// Initializes a new foreign element from an element in the native field
    pub fn from_field(field: F) -> Self {
        Self::from_biguint(field.into())
    }
}

impl<F: Field, const N: usize> Index<usize> for ForeignElement<F, N> {
    type Output = F;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.limbs[idx]
    }
}

impl<F: Field, const N: usize> IndexMut<usize> for ForeignElement<F, N> {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.limbs[idx]
    }
}

impl<F: Field, const N: usize> Debug for ForeignElement<F, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ForeignElement(")?;
        for i in 0..self.len {
            write!(f, "{:?}", self.limbs[i].to_hex())?;
            if i != self.len - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, ")")
    }
}

/// Foreign field helpers
pub trait ForeignFieldHelpers<T> {
    /// 2^{LIMB_BITS}
    fn two_to_limb() -> T;

    /// 2^{2 * LIMB_BITS}
    fn two_to_2limb() -> T;
}

impl<F: Field> ForeignFieldHelpers<F> for F {
    fn two_to_limb() -> Self {
        F::two_pow(LIMB_BITS as u64)
    }

    fn two_to_2limb() -> Self {
        F::two_to_limb().square()
    }
}

/// Foreign field helpers
pub trait BigUintForeignFieldHelpers {
    /// 2
    fn two() -> Self;

    /// 2^pow
    fn two_pow(pow: u32) -> Self;

    /// 2^{LIMB_SIZE}
    fn two_to_limb() -> Self;

    /// 2^{2 * LIMB_SIZE}
    fn two_to_2limb() -> Self;

    /// 2^t
    fn binary_modulus() -> Self;

    /// Convert to 3 limbs of LIMB_BITS each
    fn to_limbs(&self) -> [BigUint; 3];

    /// Convert to 2 limbs of 2 * LIMB_BITS each
    fn to_compact_limbs(&self) -> [BigUint; 2];

    /// Convert to 3 PrimeField limbs of LIMB_BITS each
    fn to_field_limbs<F: Field>(&self) -> [F; 3];

    /// Convert to 2 PrimeField limbs of 2 * LIMB_BITS each
    fn to_compact_field_limbs<F: Field>(&self) -> [F; 2];

    /// Negate: 2^T - self
    fn negate(&self) -> BigUint;
}

impl BigUintForeignFieldHelpers for BigUint {
    fn two() -> Self {
        Self::from(2u32)
    }

    fn two_pow(pow: u32) -> Self {
        Self::two().pow(pow)
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
        [self[0] + F::two_to_limb() * self[1], self[2]]
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
    use crate::field_helpers::FieldHelpers;
    use ark_ec::AffineCurve;
    use ark_ff::One;
    use mina_curves::pasta::Pallas as CurvePoint;
    use num_bigint::RandBigInt;
    use rand::{rngs::StdRng, SeedableRng};

    /// Base field element type
    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    const RNG_SEED: [u8; 32] = [
        12, 31, 143, 75, 29, 255, 206, 26, 67, 193, 86, 160, 1, 90, 131, 221, 86, 168, 4, 95, 50,
        48, 89, 29, 13, 250, 215, 172, 130, 24, 164, 162,
    ];

    fn secp256k1_modulus() -> BigUint {
        BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
    }

    #[test]
    fn test_big_be() {
        let big = secp256k1_modulus();
        let bytes = big.to_bytes_be();
        assert_eq!(
            ForeignElement::<BaseField, 3>::from_be(&bytes),
            ForeignElement::<BaseField, 3>::from_biguint(big)
        );
    }

    #[test]
    fn test_to_biguint() {
        let big = secp256k1_modulus();
        let bytes = big.to_bytes_be();
        let fe = ForeignElement::<BaseField, 3>::from_be(&bytes);
        assert_eq!(fe.to_biguint(), big);
    }

    #[test]
    fn test_from_biguint() {
        let one = ForeignElement::<BaseField, 3>::from_be(&[0x01]);
        assert_eq!(
            BaseField::from_biguint(&one.to_biguint()).unwrap(),
            BaseField::one()
        );

        let max_big = BaseField::modulus_biguint() - 1u32;
        let max_fe = ForeignElement::<BaseField, 3>::from_biguint(max_big.clone());
        assert_eq!(
            BaseField::from_biguint(&max_fe.to_biguint()).unwrap(),
            BaseField::from_bytes(&max_big.to_bytes_le()).unwrap(),
        );
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
        let rng = &mut StdRng::from_seed(RNG_SEED);
        for _ in 0..10 {
            rng.gen_biguint(256).negate();
        }
    }

    #[test]
    fn check_good_limbs() {
        let rng = &mut StdRng::from_seed(RNG_SEED);
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
        let rng = &mut StdRng::from_seed(RNG_SEED);
        assert_ne!(rng.gen_biguint(265).to_limbs().len(), 3);
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_2() {
        let rng = &mut StdRng::from_seed(RNG_SEED);
        assert_ne!(rng.gen_biguint(265).to_compact_limbs().len(), 2);
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_3() {
        let rng = &mut StdRng::from_seed(RNG_SEED);
        assert_ne!(rng.gen_biguint(265).to_field_limbs::<BaseField>().len(), 3);
    }

    #[test]
    #[should_panic]
    fn check_bad_limbs_4() {
        let rng = &mut StdRng::from_seed(RNG_SEED);
        assert_ne!(
            rng.gen_biguint(265)
                .to_compact_field_limbs::<BaseField>()
                .len(),
            2
        );
    }
}
