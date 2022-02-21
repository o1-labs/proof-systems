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
        ArithmeticSponge, ArithmeticSpongeParams, PlonkSpongeConstantsBasic, Sponge,
        SpongeConstants,
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

/// Transform domain prefix string to bytes
pub fn domain_prefix_to_bytes<F: PrimeField>(prefix: &str) -> Vec<u8> {
    const MAX_DOMAIN_STRING_LEN: usize = 20;
    assert!(prefix.len() <= MAX_DOMAIN_STRING_LEN);
    let prefix = &prefix[..std::cmp::min(prefix.len(), MAX_DOMAIN_STRING_LEN)];
    let mut bytes = format!("{:*<MAX_DOMAIN_STRING_LEN$}", prefix)
        .as_bytes()
        .to_vec();
    bytes.resize(F::size_in_bytes(), 0);
    bytes
}

/// Interface for hashable objects
///
/// See example in [ROInput] documentation
pub trait Hashable: Copy {
    /// Serialization to random oracle input
    fn to_roinput(self) -> ROInput;
}

/// Interface for signed objects
///
/// **Example**
///
/// ```
/// use mina_signer::{Hashable, NetworkId, ROInput, Signable};
///
/// #[derive(Clone, Copy)]
/// struct Example;
///
/// impl Hashable for Example {
///     fn to_roinput(self) -> ROInput {
///         let roi = ROInput::new();
///         // Serialize example members
///         roi
///     }
/// }
///
/// impl Signable for Example {
///     fn domain_string(network_id: NetworkId) -> &'static str {
///        match network_id {
///            NetworkId::MAINNET => "ExampleSigMainnet",
///            NetworkId::TESTNET => "ExampleSigTestnet",
///        }
///    }
/// }
/// ```
///
/// Please see [here](crate) for a more complete example.
pub trait Signable: Hashable {
    /// Returns the unique domain string for this input type on network specified by `network_id`.
    ///
    /// The domain string length must be `<= 20`.
    fn domain_string(network_id: NetworkId) -> &'static str;
}

/// Signer interface for signing [Signable] inputs and verifying [Signatures](Signature) using [Keypairs](Keypair) and [PubKeys](PubKey)
pub trait Signer {
    /// Sign `input` (see [Signable]) using keypair `kp` and return the corresponding signature.
    fn sign<S: Signable>(&mut self, kp: Keypair, input: S) -> Signature;

    /// Verify that the signature `sig` on `input` (see [Signable]) is signed with the secret key corresponding to `pub_key`.
    /// Return `true` if the signature is valid and `false` otherwise.
    fn verify<S: Signable>(&mut self, sig: Signature, pub_key: PubKey, input: S) -> bool;
}

/// Create a default signer context for network instance identified by `network_id`
///
/// **Example**
///
/// ```
/// use mina_signer::NetworkId;
///
/// let mut ctx = mina_signer::create(NetworkId::MAINNET);
/// ```
pub fn create(network_id: NetworkId) -> impl Signer {
    Schnorr::<PlonkSpongeConstantsBasic>::new(
        ArithmeticSponge::<BaseField, PlonkSpongeConstantsBasic>::new(pasta::fp::params()),
        network_id,
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
/// let mut ctx = mina_signer::custom::<poseidon::PlonkSpongeConstants5W>(
///     pasta::fp5::params(),
///     NetworkId::TESTNET,
/// );
/// ```
pub fn custom<SC: SpongeConstants>(
    params: ArithmeticSpongeParams<BaseField>,
    network_id: NetworkId,
) -> impl Signer {
    Schnorr::<SC>::new(ArithmeticSponge::<BaseField, SC>::new(params), network_id)
}
