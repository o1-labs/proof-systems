//! Primitive types for Mina transactions.

extern crate alloc;

use alloc::string::String;

use mina_curves::pasta::Fp;

/// A token identifier.
///
/// The default token ID represents the native MINA token.
/// Custom tokens have unique IDs derived from their creator's account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenId(pub Fp);

impl Default for TokenId {
    /// Returns the default MINA token ID (`Fp::from(1u64)`).
    fn default() -> Self {
        Self(Fp::from(1u64))
    }
}

/// A state hash representing a block or protocol state that an account
/// votes for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VotingFor(pub Fp);

impl Default for VotingFor {
    /// Returns the zero hash.
    fn default() -> Self {
        Self(Fp::from(0u64))
    }
}

/// A transaction memo (34 bytes).
///
/// Format: byte 0 = tag (0x01 for user), byte 1 = length,
/// bytes 2..34 = content (padded with zeros).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Memo(pub [u8; 34]);

impl Default for Memo {
    /// Returns an empty memo (all zeros).
    fn default() -> Self {
        Self::empty()
    }
}

impl Memo {
    /// Creates an empty memo (all zero bytes).
    #[must_use]
    pub const fn empty() -> Self {
        Self([0u8; 34])
    }
}

/// A unique account identifier combining a public key and token ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountId {
    /// The account's public key.
    pub public_key: mina_signer::CompressedPubKey,
    /// The token held by this account.
    pub token_id: TokenId,
}

/// A zkApp URI string (variable length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkAppUri(pub String);

/// A token symbol (short string identifier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSymbol(pub String);
