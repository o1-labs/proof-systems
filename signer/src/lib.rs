#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use ark_ec::AffineRepr;
use core::cmp::{Eq, PartialEq};
pub use keypair::Keypair;
pub use mina_curves::pasta::Pallas as CurvePoint;
use mina_hasher::{DomainParameter, Hashable};
pub use pubkey::{CompressedPubKey, PubKey};
pub use schnorr::Schnorr;
pub use seckey::SecKey;
use serde::{Deserialize, Serialize};
pub use signature::Signature;

pub mod keypair;
pub mod pubkey;
pub mod schnorr;
pub mod seckey;
pub mod signature;

/// Base field element type
pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

/// Scalar field element type
pub type ScalarField = <CurvePoint as AffineRepr>::ScalarField;

/// Mina network (or blockchain) identifier
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NetworkId {
    /// Id for all testnets
    TESTNET = 0x00,

    /// Id for mainnet
    MAINNET = 0x01,
}

impl From<NetworkId> for u8 {
    fn from(id: NetworkId) -> Self {
        id as Self
    }
}

impl NetworkId {
    /// Convert the network ID to its domain string representation for
    /// cryptographic hashing.
    ///
    /// This is used in the `Hashable` trait's `domain_string` method to provide
    /// domain separation for signature hashing.
    ///
    /// Returns:
    /// - `"MinaSignatureMainnet"` for `NetworkId::MAINNET`
    /// - `"CodaSignature"` for `NetworkId::TESTNET`
    #[must_use]
    pub fn into_domain_string(self) -> String {
        match self {
            Self::MAINNET => "MinaSignatureMainnet".to_string(),
            Self::TESTNET => "CodaSignature".to_string(),
        }
    }
}

impl DomainParameter for NetworkId {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}

/// Nonce derivation mode for signature generation.
///
/// Controls how the deterministic nonce is derived during signing.
/// Different transaction types require different nonce derivation methods.
///
/// These modes correspond to the `Message.Legacy` and `Message.Chunked` modules
/// in the OCaml Mina implementation (`src/lib/crypto/signature_lib/schnorr.ml`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NonceMode {
    /// Legacy nonce derivation for user commands.
    ///
    /// Use this mode for legacy Mina transactions (user commands) such as
    /// payments and delegations. This corresponds to `Message.Legacy` in
    /// the OCaml implementation.
    ///
    /// Uses direct byte serialization (`ROInput.to_bytes()`) for nonce derivation.
    Legacy,

    /// Chunked nonce derivation for zkApp transactions.
    ///
    /// Use this mode for zkApp transactions. This mode is compatible with
    /// o1js and uses field packing for nonce derivation. This corresponds
    /// to `Message.Chunked` in the OCaml implementation.
    ///
    /// Uses field packing (`ROInput.to_fields()`) then bit conversion for
    /// nonce derivation.
    Chunked,
}

/// Interface for signed objects
///
/// Signer interface for signing [`Hashable`] inputs and verifying
/// [`Signatures`](Signature) using [`Keypairs`](Keypair) and
/// [`PubKeys`](PubKey)
pub trait Signer<H: Hashable> {
    /// Sign `input` (see [`Hashable`]) using keypair `kp` and return the
    /// corresponding signature.
    ///
    /// # Parameters
    ///
    /// * `kp` - The keypair to use for signing
    /// * `input` - The message to sign (must implement [`Hashable`])
    /// * `nonce_mode` - Controls nonce derivation method:
    ///   - [`NonceMode::Legacy`]: For user commands (payments, delegations)
    ///   - [`NonceMode::Chunked`]: For zkApp transactions (o1js compatible)
    ///
    /// # Returns
    ///
    /// A [`Signature`] over the input message.
    fn sign(&mut self, kp: &Keypair, input: &H, nonce_mode: NonceMode) -> Signature;

    /// Verify that the signature `sig` on `input` (see [`Hashable`]) is signed
    /// with the secret key corresponding to `pub_key`.
    /// Return `true` if the signature is valid and `false` otherwise.
    fn verify(&mut self, sig: &Signature, pub_key: &PubKey, input: &H) -> bool;
}

/// Create a legacy signer context with domain parameters initialized with
/// `domain_param`
///
/// **Example**
///
/// ```
/// #[path = "../tests/transaction.rs"]
/// mod transaction;
/// use mina_signer::{NetworkId, self, Signer};
/// use transaction::Transaction;
///
/// let mut ctx = mina_signer::create_legacy::<Transaction>(NetworkId::TESTNET);
/// ```
pub fn create_legacy<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    schnorr::create_legacy::<H>(domain_param)
}

/// Create a kimchi signer context for `ZkApp` signing (Berkeley upgrade)
/// with domain parameters initialized with `domain_param`
///
/// **Example**
///
/// ```
/// #[path = "../tests/transaction.rs"]
/// mod transaction;
/// use mina_signer::{NetworkId, self, Signer};
/// use transaction::Transaction;
///
/// let mut ctx = mina_signer::create_kimchi::<Transaction>(NetworkId::TESTNET);
/// ```
pub fn create_kimchi<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    schnorr::create_kimchi::<H>(domain_param)
}
