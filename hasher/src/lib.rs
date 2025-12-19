#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

pub mod poseidon;
pub mod roinput;
pub use mina_curves::pasta::Fp;
pub use poseidon::{PoseidonHasherKimchi, PoseidonHasherLegacy};
pub use roinput::ROInput;

use ark_ff::PrimeField;
use o1_utils::FieldHelpers;

/// Maximum length for domain strings used in hashing.
const MAX_DOMAIN_STRING_LEN: usize = 20;

/// The domain parameter trait is used during hashing to convey extra
/// arguments to domain string generation. It is also used by generic signing
/// code.
pub trait DomainParameter: Clone {
    /// Conversion into vector of bytes
    fn into_bytes(self) -> Vec<u8>;
}

impl DomainParameter for () {
    fn into_bytes(self) -> Vec<u8> {
        vec![]
    }
}

impl DomainParameter for u32 {
    fn into_bytes(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl DomainParameter for u64 {
    fn into_bytes(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

/// Interface for hashable objects
///
/// Mina uses fixed-length hashing with domain separation for each type of
/// object hashed. The prior means that `Hashable` only supports types whose
/// size is not variable.
///
/// **Important:** The developer MUST assure that all domain strings used
/// throughout the system are unique and that all structures hashed are of fixed
/// size.
///
/// Here is an example of how to implement the `Hashable` trait for am `Example`
/// type.
///
/// ```rust
/// use mina_hasher::{Hashable, ROInput};
///
/// #[derive(Clone)]
/// struct Example;
///
/// impl Hashable for Example {
///     type D = ();
///
///     fn to_roinput(&self) -> ROInput {
///         let roi = ROInput::new();
///         // Serialize example members
///         // ...
///         roi
///     }
///
///     fn domain_string(_: Self::D) -> Option<String> {
///        format!("Example").into()
///    }
/// }
/// ```
///
/// See example in [`ROInput`] documentation
pub trait Hashable: Clone {
    /// Generic domain string argument type
    type D: DomainParameter;

    /// Serialization to random oracle input
    fn to_roinput(&self) -> ROInput;

    /// Generate unique domain string of length `<= 20`.
    ///
    /// The length bound is guarded by an assertion, but uniqueness must be
    /// enforced by the developer implementing the traits (see [`Hashable`] for
    /// more details). The domain string may be parameterized by the contents of
    /// the generic `domain_param` argument.
    ///
    /// **Note:** You should always return `Some(String)`. A `None` return value
    /// is only used for testing.
    fn domain_string(domain_param: Self::D) -> Option<String>;
}

/// Interface for hashing [`Hashable`] inputs
///
/// Mina uses a unique hasher configured with domain separation for each type of
/// object hashed.
/// The underlying hash parameters are large and costly to initialize, so the
/// [`Hasher`] interface provides a reusable context for efficient hashing with
/// domain separation.
///
/// Example usage
///
/// ```rust
/// use mina_hasher::{create_legacy, Fp, Hashable, Hasher, ROInput};
///
/// #[derive(Clone)]
/// struct Something;
///
/// impl Hashable for Something {
///     type D = u32;
///
///     fn to_roinput(&self) -> ROInput {
///         let mut roi = ROInput::new();
///         // ... serialize contents of self
///         roi
///     }
///
///     fn domain_string(id: Self::D) -> Option<String> {
///         format!("Something {}", id).into()
///     }
/// }
///
/// let mut hasher = create_legacy::<Something>(123);
/// let output: Fp = hasher.hash(&Something { });
/// ```
///
pub trait Hasher<H: Hashable> {
    /// Set the initial state based on domain separation string generated from
    /// `H::domain_string(domain_param)`
    fn init(&mut self, domain_param: H::D) -> &mut dyn Hasher<H>;

    /// Restore the initial state that was set most recently
    fn reset(&mut self) -> &mut dyn Hasher<H>;

    /// Consume hash `input`
    fn update(&mut self, input: &H) -> &mut dyn Hasher<H>;

    /// Obtain has result output
    fn digest(&mut self) -> Fp;

    /// Hash input and obtain result output
    fn hash(&mut self, input: &H) -> Fp {
        self.reset();
        self.update(input);
        let output = self.digest();
        self.reset();
        output
    }

    /// Initialize state, hash input and obtain result output
    fn init_and_hash(&mut self, domain_param: H::D, input: &H) -> Fp {
        self.init(domain_param);
        self.update(input);
        let output = self.digest();
        self.reset();
        output
    }
}

/// Transform domain prefix string to field element.
///
/// The prefix must be at most 20 characters. Shorter strings are
/// right-padded with asterisks (`*`) to reach 20 characters before
/// conversion to a field element. For example, `"CodaSignature"` becomes
/// `"CodaSignature*******"`.
fn domain_prefix_to_field<F: PrimeField>(prefix: String) -> F {
    assert!(prefix.len() <= MAX_DOMAIN_STRING_LEN);
    let prefix = &prefix[..core::cmp::min(prefix.len(), MAX_DOMAIN_STRING_LEN)];
    let mut bytes = format!("{prefix:*<MAX_DOMAIN_STRING_LEN$}")
        .as_bytes()
        .to_vec();
    bytes.resize(F::size_in_bytes(), 0);
    F::from_bytes(&bytes).expect("invalid domain bytes")
}

/// Create a legacy hasher context
pub fn create_legacy<H: Hashable>(domain_param: H::D) -> PoseidonHasherLegacy<H> {
    poseidon::new_legacy::<H>(domain_param)
}

/// Create a kimchi hasher context for ZkApp signing (Berkeley upgrade)
pub fn create_kimchi<H: Hashable>(domain_param: H::D) -> PoseidonHasherKimchi<H>
where
    H::D: DomainParameter,
{
    poseidon::new_kimchi::<H>(domain_param)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_domain_prefix_padding_short_string() {
        // "CodaSignature" (13 chars) should be padded to "CodaSignature*******"
        let result: Fp = domain_prefix_to_field("CodaSignature".to_string());
        let bytes = result.to_bytes();
        let padded = &bytes[..MAX_DOMAIN_STRING_LEN];
        assert_eq!(padded, b"CodaSignature*******");
    }

    #[test]
    fn test_domain_prefix_padding_exact_length() {
        // Exactly 20 chars should not be padded
        let result: Fp = domain_prefix_to_field("MinaSignatureMainnet".to_string());
        let bytes = result.to_bytes();
        let padded = &bytes[..MAX_DOMAIN_STRING_LEN];
        assert_eq!(padded, b"MinaSignatureMainnet");
    }

    #[test]
    fn test_domain_prefix_padding_empty_string() {
        // Empty string should become 20 asterisks
        let result: Fp = domain_prefix_to_field("".to_string());
        let bytes = result.to_bytes();
        let padded = &bytes[..MAX_DOMAIN_STRING_LEN];
        assert_eq!(padded, b"********************");
    }

    #[test]
    fn test_domain_prefix_same_result_with_or_without_padding() {
        // Pre-padded and un-padded versions should produce the same result
        let unpadded: Fp = domain_prefix_to_field("CodaSignature".to_string());
        let prepadded: Fp = domain_prefix_to_field("CodaSignature*******".to_string());
        assert_eq!(unpadded, prepadded);
    }

    #[test]
    #[should_panic]
    fn test_domain_prefix_too_long() {
        // Strings longer than 20 chars should panic
        let _: Fp = domain_prefix_to_field("ThisStringIsTooLongForDomain".to_string());
    }
}
