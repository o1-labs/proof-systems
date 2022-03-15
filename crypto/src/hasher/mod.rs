//! Mina hasher module
//!
//! An abstract hashing interface and associated traits
//!
//! **Example**
//! ```rust
//! use mina_crypto::hasher::{create_legacy, Hashable, Hasher, ROInput};
//!
//! #[derive(Clone)]
//! struct Example {
//!     a: u32,
//!     b: u64,
//! }
//!
//! impl Hashable for Example {
//!     type D = ();
//!
//!     fn to_roinput(self) -> ROInput {
//!         let mut roi = ROInput::new();
//!         roi.append_u32(self.a);
//!         roi.append_u64(self.b);
//!         roi
//!     }
//!
//!     fn domain_string(_: Option<Self>, _: &Self::D) -> String {
//!         format!("Example")
//!     }
//! }
//!
//! // Usage example
//! let mut hasher = create_legacy::<Example>(());
//! let out = hasher.hash(Example {a: 1, b: 2});

pub mod poseidon;
pub mod roinput;

use ark_ff::PrimeField;
use mina_curves::pasta::Fp;
use o1_utils::FieldHelpers;
pub use roinput::ROInput;

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
/// use mina_crypto::{
///     hasher::{Hashable, ROInput},
///     signer::NetworkId,
/// };
///
/// #[derive(Clone)]
/// struct Example;
///
/// impl Hashable for Example {
///     type D = NetworkId;
///
///     fn to_roinput(self) -> ROInput {
///         let roi = ROInput::new();
///         // Serialize example members
///         // ...
///         roi
///     }
///
///     fn domain_string(_: Option<Self>, network_id: &NetworkId) -> String {
///        match network_id {
///            NetworkId::MAINNET => "ExampleMainnet",
///            NetworkId::TESTNET => "ExampleTestnet",
///        }.to_string()
///    }
/// }
/// ```
///
/// See example in [`ROInput`] documentation
pub trait Hashable: Clone {
    /// Generic domain string argument type
    type D: DomainParameter;

    /// Serialization to random oracle input
    fn to_roinput(self) -> ROInput;

    /// Generate unique domain string of length `<= 20`.
    ///   The domain string may be parameterized by the contents of `this`
    ///   and/or the generic `domain_param` argument.
    fn domain_string(this: Option<Self>, domain_param: &Self::D) -> String;
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
/// use mina_crypto::hasher::{create_legacy, Hashable, Hasher, ROInput};
///
/// use mina_curves::pasta::Fp;
///
/// #[derive(Clone)]
/// struct Something;
///
/// impl Hashable for Something {
///     type D = u32;
///
///     fn to_roinput(self) -> ROInput {
///         let mut roi = ROInput::new();
///         // ... serialize contents of self
///         roi
///     }
///
///     fn domain_string(_: Option<Self>, id: &Self::D) -> String {
///         format!("Something {}", id)
///     }
/// }
///
/// let mut hasher = create_legacy::<Something>(123);
/// let output: Fp = hasher.hash(Something { });
/// ```
///
pub trait Hasher<H: Hashable> {
    /// Set the initial state based on domain separation string
    /// generated from `H::domain_string(None, domain_param)`
    fn init(&mut self, domain_param: H::D) -> &mut dyn Hasher<H>;

    /// Restore the initial state that was set most recently
    fn reset(&mut self) -> &mut dyn Hasher<H>;

    /// Consume hash `input`
    fn update(&mut self, input: H) -> &mut dyn Hasher<H>;

    /// Obtain has result output
    fn digest(&mut self) -> Fp;

    /// Hash input and obtain result output
    fn hash(&mut self, input: H) -> Fp {
        self.reset();
        self.update(input);
        let output = self.digest();
        self.reset();
        output
    }

    /// Initialize state, hash input and obtain result output
    fn init_and_hash(&mut self, domain_param: H::D, input: H) -> Fp {
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
pub fn create_legacy<H: Hashable>(domain_param: H::D) -> impl Hasher<H>
where
    H::D: DomainParameter,
{
    poseidon::new_legacy::<H>(domain_param)
}

/// Create an experimental kimchi hasher context
pub fn create_kimchi<H: Hashable>(domain_param: H::D) -> impl Hasher<H>
where
    H::D: DomainParameter,
{
    poseidon::new_kimchi::<H>(domain_param)
}

#[cfg(test)]
mod tests {
    use crate::hasher::{create_legacy, Hashable, Hasher, ROInput};

    #[test]
    fn interfaces() {
        #[derive(Clone)]
        struct Foo {
            x: u32,
            y: u64,
        }

        impl Hashable for Foo {
            type D = u64;

            fn to_roinput(self) -> ROInput {
                let mut roi = ROInput::new();
                roi.append_u32(self.x);
                roi.append_u64(self.y);

                roi
            }

            fn domain_string(_: Option<Self>, id: &u64) -> String {
                format!("Foo {}", id)
            }
        }

        // Usage 1: incremental interface
        let mut hasher = create_legacy::<Foo>(0);
        hasher.update(Foo { x: 3, y: 1 });
        let x1 = hasher.digest(); // Resets to previous init state (0)
        hasher.update(Foo { x: 82, y: 834 });
        hasher.update(Foo { x: 1235, y: 93 });
        hasher.digest(); // Resets to previous init state (0)
        hasher.init(1);
        hasher.update(Foo { x: 82, y: 834 });
        let x2 = hasher.digest(); // Resets to previous init state (1)

        // Usage 2: builder interface with one-shot pattern
        let mut hasher = create_legacy::<Foo>(0);
        let y1 = hasher.update(Foo { x: 3, y: 1 }).digest(); // Resets to previous init state (0)
        hasher.update(Foo { x: 31, y: 21 }).digest();

        // Usage 3: builder interface with one-shot pattern also setting init state
        let mut hasher = create_legacy::<Foo>(0);
        let y2 = hasher.init(0).update(Foo { x: 3, y: 1 }).digest(); // Resets to previous init state (1)
        let y3 = hasher.init(1).update(Foo { x: 82, y: 834 }).digest(); // Resets to previous init state (2)

        // Usage 4: one-shot interfaces
        let mut hasher = create_legacy::<Foo>(0);
        let y4 = hasher.hash(Foo { x: 3, y: 1 });
        let y5 = hasher.init_and_hash(1, Foo { x: 82, y: 834 });

        assert_eq!(x1, y1);
        assert_eq!(x1, y2);
        assert_eq!(x2, y3);
        assert_eq!(x1, y4);
        assert_eq!(x2, y5);
        assert_ne!(x1, y5);
        assert_ne!(x2, y4);
        assert_ne!(x1, y3);
        assert_ne!(x2, y2);
    }
}
