//! This module provides the [`CryptoDigest`] trait,
//! which provides a generic interface for hashing.
//!
//! To use it, simply implement [`CryptoDigest`] for your type:
//!
//! ```
//! use o1_utils::hasher::CryptoDigest;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct A {
//!     thing: u8,
//! }
//!
//! impl CryptoDigest for A {
//!     const PREFIX: &'static [u8; 15] = b"kimchi-circuit0";
//! }
//!
//! let a = A { thing: 1 };
//! let expected_result = [164, 8, 215, 27, 25, 36, 6, 167, 42, 86, 200, 203, 99, 74, 178, 134, 66, 168, 85, 7, 224, 189, 73, 63, 117, 23, 18, 193, 168, 176, 123, 80];
//! assert_eq!(a.digest(), expected_result);
//!
//! let b = A { thing: 1 };
//! assert_eq!(a.digest(), b.digest());
//! ```
//!
//! Warning: make sure not to reuse the same `PREFIX`
//! for different types. This prefix is here to semantically
//! distinguish the hash of different types
//! (and thus different use-case).
//!

use serde::Serialize;
use sha2::{Digest, Sha256};

/// This trait can be implemented on any type that implements [`serde::Serialize`],
/// in order to provide a `digest()` function that returns a unique hash.
pub trait CryptoDigest: Serialize {
    /// The domain separation string to use in the hash.
    /// This is to distinguish hashes for different use-cases.
    /// With this approach, a type is linked to a single usecase.
    ///
    /// Warning: careful not to use the same separation string with
    /// two different types.
    const PREFIX: &'static [u8; 15];

    /// Returns the digest of `self`.
    /// Note: this is implemented as the SHA-256 of a prefix
    /// ("kimchi-circuit"), followed by the serialized gates.
    /// The gates are serialized using [BCS](https://github.com/diem/bcs).
    fn digest(&self) -> [u8; 32] {
        // compute the prefixed state lazily
        let mut hasher = Sha256::new();
        hasher.update(Self::PREFIX);
        hasher.update(
            bcs::to_bytes(self).unwrap_or_else(|e| panic!("couldn't serialize the gate: {e}")),
        );
        hasher.finalize().into()
    }
}
