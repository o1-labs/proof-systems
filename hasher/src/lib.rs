#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod poseidon;
pub mod roinput;
pub use mina_curves::pasta::Fp;
pub use poseidon::{PoseidonHasherKimchi, PoseidonHasherLegacy};
pub use roinput::ROInput;

#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
use o1_utils::FieldHelpers;

/// The domain parameter trait is used during hashing to convey extra
/// arguments to domain string generation.  It is also used by generic signing code.
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
/// Mina uses fixed-length hashing with domain separation for each type of object hashed.
/// The prior means that `Hashable` only supports types whose size is not variable.
///
/// **Important:** The developer MUST assure that all domain strings used throughout the
/// system are unique and that all structures hashed are of fixed size.
///
/// Here is an example of how to implement the `Hashable` trait for am `Example` type.
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
    /// The length bound is guarded by an assertion, but uniqueness must
    /// be enforced by the developer implementing the traits (see [`Hashable`] for
    /// more details). The domain string may be parameterized by the contents of
    /// the generic `domain_param` argument.
    ///
    /// **Note:** You should always return `Some(String)`. A `None` return value
    /// is only used for testing.
    fn domain_string(domain_param: Self::D) -> Option<String>;
}

/// Interface for hashing [`Hashable`] inputs
///
/// Mina uses a unique hasher configured with domain separation for each type of object hashed.
/// The underlying hash parameters are large and costly to initialize, so the [`Hasher`] interface
/// provides a reusable context for efficient hashing with domain separation.
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
    /// Set the initial state based on domain separation string
    /// generated from `H::domain_string(domain_param)`
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

/// Transform domain prefix string to field element
fn domain_prefix_to_field<F: PrimeField>(prefix: String) -> F {
    const MAX_DOMAIN_STRING_LEN: usize = 20;
    assert!(prefix.len() <= MAX_DOMAIN_STRING_LEN);
    let prefix = &prefix[..std::cmp::min(prefix.len(), MAX_DOMAIN_STRING_LEN)];
    let mut bytes = format!("{:*<MAX_DOMAIN_STRING_LEN$}", prefix)
        .as_bytes()
        .to_vec();
    bytes.resize(F::size_in_bytes(), 0);
    F::from_bytes(&bytes).expect("invalid domain bytes")
}

/// Create a legacy hasher context
pub fn create_legacy<'a, H: Hashable>(domain_param: H::D) -> PoseidonHasherLegacy<'a, H> {
    poseidon::new_legacy::<'a, H>(domain_param)
}

/// Create an experimental kimchi hasher context
pub fn create_kimchi<'a, H: Hashable>(domain_param: H::D) -> PoseidonHasherKimchi<'a, H>
where
    H::D: DomainParameter,
{
    poseidon::new_kimchi::<'a, H>(domain_param)
}
