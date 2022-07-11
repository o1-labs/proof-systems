#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod keypair;
pub mod pubkey;
pub mod schnorr;
pub mod seckey;
pub mod signature;

use mina_hasher::{DomainParameter, Hashable};

pub use keypair::Keypair;
pub use pubkey::{CompressedPubKey, PubKey};
pub use schnorr::Schnorr;
pub use seckey::SecKey;
pub use signature::Signature;

use ark_ec::AffineCurve;
use mina_curves::pasta::pallas;

/// Affine curve point type
pub use pallas::Affine as CurvePoint;
/// Base field element type
pub type BaseField = <CurvePoint as AffineCurve>::BaseField;
/// Scalar field element type
pub type ScalarField = <CurvePoint as AffineCurve>::ScalarField;

/// Mina network (or blockchain) identifier
#[derive(Debug, Clone)]
pub enum NetworkId {
    /// Id for all testnets
    TESTNET = 0x00,

    /// Id for mainnet
    MAINNET = 0x01,
}

impl From<NetworkId> for u8 {
    fn from(id: NetworkId) -> u8 {
        id as u8
    }
}

impl DomainParameter for NetworkId {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}

/// Interface for signed objects
///
/// Signer interface for signing [`Hashable`] inputs and verifying [`Signatures`](Signature) using [`Keypairs`](Keypair) and [`PubKeys`](PubKey)
pub trait Signer<H: Hashable> {
    /// Sign `input` (see [`Hashable`]) using keypair `kp` and return the corresponding signature.
    fn sign(&mut self, kp: &Keypair, input: &H) -> Signature;

    /// Verify that the signature `sig` on `input` (see [`Hashable`]) is signed with the secret key corresponding to `pub_key`.
    /// Return `true` if the signature is valid and `false` otherwise.
    fn verify(&mut self, sig: &Signature, pub_key: &PubKey, input: &H) -> bool;
}

/// Create a legacy signer context with domain parameters initialized with `domain_param`
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

/// Create an experimental kimchi signer context with domain parameters initialized with `domain_param`
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
