//! Mina signer module
//!
//! An abstract signing interface and associated traits
//!
//! **Example**
//!
//! ```rust
//! #[path = "../../tests/transaction.rs"]
//! mod transaction;
//!
//! use rand;
//! use mina_crypto::signer::{NetworkId, Keypair, PubKey, Signer};
//! use transaction::Transaction;
//!
//! let keypair = Keypair::rand(&mut rand::rngs::OsRng);
//!
//! let tx = Transaction::new_payment(
//!                 keypair.public,
//!                 PubKey::from_address("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt").expect("invalid receiver address"),
//!                 1729000000000,
//!                 2000000000,
//!                 271828,
//!             );
//!
//! let mut ctx = mina_crypto::signer::create_legacy::<Transaction>(NetworkId::TESTNET);
//! let sig = ctx.sign(keypair, tx);
//! assert!(ctx.verify(sig, keypair.public,tx));
//! ```

pub mod keypair;
pub mod pubkey;
pub mod schnorr;
pub mod seckey;
pub mod signature;

use crate::hasher::{DomainParameter, Hashable};

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
#[derive(Copy, Clone)]
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
/// Signer interface for signing [Hashable] inputs and verifying [Signatures](Signature) using [Keypairs](Keypair) and [PubKeys](PubKey)
pub trait Signer<H: Hashable> {
    /// Sign `input` (see [Hashable]) using keypair `kp` and return the corresponding signature.
    fn sign(&mut self, kp: Keypair, input: H) -> Signature;

    /// Verify that the signature `sig` on `input` (see [Hashable]) is signed with the secret key corresponding to `pub_key`.
    /// Return `true` if the signature is valid and `false` otherwise.
    fn verify(&mut self, sig: Signature, pub_key: PubKey, input: H) -> bool;
}

/// Create a legacy signer context with domain parameters initialized with `domain_param`
///
/// **Example**
///
/// ```ignore
/// let mut ctx = mina_crypto::signer::create_legacy::<Transaction>(NetworkId::TESTNET);
/// ```
pub fn create_legacy<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    schnorr::create_legacy::<H>(domain_param)
}

/// Create an experimental kimchi signer context with domain parameters initialized with `domain_param`
///
/// **Example**
///
/// ```ignore
/// let mut ctx = mina_crypto::signer::create_kimchi::<Transaction>(NetworkId::TESTNET);
/// ```
pub fn create_kimchi<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    schnorr::create_kimchi::<H>(domain_param)
}

#[cfg(test)]
mod test {
    use crate::hasher::{DomainParameter, Hashable, ROInput};
    use crate::signer::ScalarField;

    #[test]
    fn test_example1() {
        #[derive(Clone, Copy)]
        struct MerkleIndexNode {
            left: ScalarField,
            right: ScalarField,
        }

        impl DomainParameter for u16 {
            fn into_bytes(self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
        }

        impl Hashable for MerkleIndexNode {
            type D = u16;

            fn to_roinput(self) -> ROInput {
                let mut roi = ROInput::new();

                roi.append_scalar(self.left);
                roi.append_scalar(self.right);

                roi
            }

            fn domain_string(_: Option<Self>, height: &u16) -> String {
                format!("MerkleTree{:03}", height)
            }
        }
    }

    #[test]
    fn test_example2() {
        #[derive(Clone, Copy)]
        struct MerkleIndexNode {
            height: u16,
            left: ScalarField,
            right: ScalarField,
        }

        impl Hashable for MerkleIndexNode {
            type D = ();

            fn to_roinput(self) -> ROInput {
                let mut roi = ROInput::new();

                roi.append_scalar(self.left);
                roi.append_scalar(self.right);

                roi
            }

            fn domain_string(this: Option<Self>, _: &()) -> String {
                match this {
                    Some(x) => format!("MerkleTree{:03}", x.height),
                    None => panic!("missing this parameter (should never happen)"),
                }
            }
        }
    }
}
