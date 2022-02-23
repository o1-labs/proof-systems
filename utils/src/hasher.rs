//! This module includes the [CryptoDigest] trait,
//! which provides a generic interface for hashing.
//!
//! To use it, simply implement [CryptoDigest] for your type:
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
//! let expected_result = [190, 149, 126, 83, 64, 202, 220, 210, 10, 145, 208, 164, 52, 140, 137, 120, 25, 116, 213, 144, 224, 43, 112, 166, 160, 157, 43, 125, 7, 174, 249, 230];
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
    /// The gates are serialized using messagepack.
    fn digest(&self) -> [u8; 32] {
        // compute the prefixed state lazily
        let mut hasher = Sha256::new();
        hasher.update(Self::PREFIX);
        hasher.update(&rmp_serde::to_vec(self).expect("couldn't serialize the gate"));
        hasher.finalize().into()
    }
}
