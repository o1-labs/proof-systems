#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod keypair;
pub mod pubkey;
pub mod roinput;
pub mod schnorr;
pub mod seckey;
pub mod signature;

use ark_ff::PrimeField;
pub use keypair::Keypair;
use o1_utils::FieldHelpers;
pub use pubkey::{CompressedPubKey, PubKey};
pub use roinput::ROInput;
pub use schnorr::Schnorr;
pub use seckey::SecKey;
pub use signature::Signature;

use oracle::{
    pasta,
    poseidon::{
        ArithmeticSponge, ArithmeticSpongeParams, PlonkSpongeConstants15W,
        PlonkSpongeConstantsBasic, Sponge, SpongeConstants,
    },
};

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

/// Transform domain prefix string to field element
pub fn domain_prefix_to_field<F: PrimeField>(prefix: String) -> F {
    const MAX_DOMAIN_STRING_LEN: usize = 20;
    assert!(prefix.len() <= MAX_DOMAIN_STRING_LEN);
    let prefix = &prefix[..std::cmp::min(prefix.len(), MAX_DOMAIN_STRING_LEN)];
    let mut bytes = format!("{:*<MAX_DOMAIN_STRING_LEN$}", prefix)
        .as_bytes()
        .to_vec();
    bytes.resize(F::size_in_bytes(), 0);
    F::from_bytes(&bytes).expect("invalid domain bytes")
}

/// Domain parameter
pub trait DomainParameter: Clone {
    /// Conversion into bytes
    fn into_bytes(self) -> Vec<u8>;
}

impl DomainParameter for () {
    fn into_bytes(self) -> Vec<u8> {
        vec![]
    }
}

impl DomainParameter for NetworkId {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
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
/// **Example**
///
/// ```
/// use mina_signer::{Hashable, NetworkId, ROInput};
///
/// #[derive(Clone)]
/// struct Example;
///
/// impl Hashable<NetworkId> for Example {
///     fn to_roinput(self) -> ROInput {
///         let roi = ROInput::new();
///         // Serialize example members
///         roi
///     }
///
///     fn domain_string(self, network_id: &NetworkId) -> String {
///        match network_id {
///            NetworkId::MAINNET => "ExampleSigMainnet",
///            NetworkId::TESTNET => "ExampleSigTestnet",
///        }.to_string()
///    }
/// }
/// ```
///
/// See example in [ROInput] documentation
pub trait Hashable<D: DomainParameter>: Clone {
    /// Serialization to random oracle input
    fn to_roinput(self) -> ROInput;

    /// Returns the unique domain string
    /// The domain string length must be `<= 20`.
    fn domain_string(self, arg: &D) -> String;
}

/// Interface for signed objects
///
/// Signer interface for signing [Hashable] inputs and verifying [Signatures](Signature) using [Keypairs](Keypair) and [PubKeys](PubKey)
pub trait Signer<D: DomainParameter> {
    // IDEA 2 <- Signer can only work when associated type is NetworkId :-(
    /// Sign `input` (see [Hashable]) using keypair `kp` and return the corresponding signature.
    fn sign<H: Hashable<D>>(&mut self, kp: Keypair, input: H) -> Signature;

    /// Verify that the signature `sig` on `input` (see [Hashable]) is signed with the secret key corresponding to `pub_key`.
    /// Return `true` if the signature is valid and `false` otherwise.
    fn verify<H: Hashable<D>>(&mut self, sig: Signature, pub_key: PubKey, input: H) -> bool;
}

/// Create a legacy signer context for network instance identified by `network_id`
///
/// **Example**
///
/// ```
/// use mina_signer::NetworkId;
///
/// let mut ctx = mina_signer::create_legacy::<NetworkId>(NetworkId::TESTNET);
/// ```
pub fn create_legacy<D: DomainParameter>(domain_param: D) -> impl Signer<D> {
    Schnorr::<PlonkSpongeConstantsBasic, D>::new(
        ArithmeticSponge::<BaseField, PlonkSpongeConstantsBasic>::new(pasta::fp::params()),
        domain_param,
    )
}

/// Create an (experimental) kimchi signer context for network instance identified by `network_id`
///
/// **Example**
///
/// ```
/// use mina_signer::NetworkId;
///
/// let mut ctx = mina_signer::create_kimchi::<NetworkId>(NetworkId::TESTNET);
/// ```
pub fn create_kimchi<D: DomainParameter>(domain_param: D) -> impl Signer<D> {
    Schnorr::<PlonkSpongeConstants15W, D>::new(
        ArithmeticSponge::<BaseField, PlonkSpongeConstants15W>::new(pasta::fp::params()),
        domain_param,
    )
}

/// Create a custom signer context for network instance identified by `network_id` using custom sponge parameters `params`
///
/// **Example**
///
/// ```
/// use mina_signer::NetworkId;
/// use oracle::{pasta, poseidon};
///
/// let mut ctx = mina_signer::create_custom::<poseidon::PlonkSpongeConstants15W, NetworkId>(
///     pasta::fp::params(),
///     NetworkId::TESTNET,
/// );
/// ```
pub fn create_custom<SC: SpongeConstants, D: DomainParameter>(
    params: ArithmeticSpongeParams<BaseField>,
    domain_param: D,
) -> impl Signer<D> {
    Schnorr::<SC, D>::new(ArithmeticSponge::<BaseField, SC>::new(params), domain_param)
}

#[cfg(test)]
mod test {
    use crate::{Hashable, ROInput, ScalarField};

    #[test]
    fn test_example1() {
        #[derive(Clone, Copy)]
        struct MerkleIndexNode {
            left: ScalarField,
            right: ScalarField,
        }

        impl Hashable<u64> for MerkleIndexNode {
            fn to_roinput(self) -> ROInput {
                let mut roi = ROInput::new();

                roi.append_scalar(self.left);
                roi.append_scalar(self.right);

                roi
            }

            fn domain_string(self, height: &u64) -> String {
                format!("MerkleTree{:03}", height)
            }
        }
    }

    #[test]
    fn test_example2() {
        #[derive(Clone, Copy)]
        struct MerkleIndexNode {
            height: u64,
            left: ScalarField,
            right: ScalarField,
        }

        impl Hashable<()> for MerkleIndexNode {
            fn to_roinput(self) -> ROInput {
                let mut roi = ROInput::new();

                roi.append_scalar(self.left);
                roi.append_scalar(self.right);

                roi
            }

            fn domain_string(self, _: &()) -> String {
                format!("MerkleTree{:03}", self.height)
            }
        }
    }
}
