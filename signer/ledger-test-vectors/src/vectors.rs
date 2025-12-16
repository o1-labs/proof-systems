//! Test Vector Generation for Mina Ledger Signing
//!
//! This module generates comprehensive test vectors for validating
//! Mina Ledger hardware wallet signing implementations.
//!
//! # Test Vector Format
//!
//! Test vectors are serialized as JSON with the following structure:
//!
//! ```json
//! {
//!   "test_vectors": [
//!     {
//!       "account": 0,
//!       "private_key": "hex-encoded scalar",
//!       "public_key": {
//!         "x": "hex-encoded field element",
//!         "y": "hex-encoded field element"
//!       },
//!       "address": "B62...",
//!       "network_id": 1,
//!       "transaction": { ... },
//!       "signature": {
//!         "rx": "hex-encoded field element",
//!         "s": "hex-encoded scalar"
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! # Coverage
//!
//! The generated test vectors cover:
//! - Multiple account indices (0, 1, 2, ...)
//! - Both mainnet and testnet network IDs
//! - Payment transactions with various amounts
//! - Delegation transactions
//! - Different memo values
//! - Edge cases (max amounts, zero amounts, etc.)

use crate::transaction::{Transaction, TransactionJson};
use mina_bip32::ExtendedPrivateKey;
use mina_signer::{Keypair, NetworkId, PubKey, SecKey, Signer};
use o1_utils::FieldHelpers;
use serde::{Deserialize, Serialize};

/// Public key representation for JSON serialization
///
/// Contains both the x and y coordinates of the public key point
/// on the Pallas curve.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyJson {
    /// X-coordinate of the public key point (hex-encoded, little-endian)
    pub x: String,
    /// Y-coordinate of the public key point (hex-encoded, little-endian)
    pub y: String,
}

/// Signature representation for JSON serialization
///
/// A Mina signature consists of:
/// - `rx`: The x-coordinate of the nonce point R = k * G
/// - `s`: The scalar s = k + e * sk, where e is the challenge hash
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureJson {
    /// X-coordinate of the nonce point R (hex-encoded, little-endian)
    ///
    /// This is the first 32 bytes of the signature
    pub rx: String,

    /// Scalar component of the signature (hex-encoded, little-endian)
    ///
    /// Computed as s = k + e * sk where:
    /// - k is the nonce
    /// - e is the challenge (Poseidon hash)
    /// - sk is the secret key
    pub s: String,
}

/// A single test vector entry
///
/// Contains all information needed to verify a signing implementation:
/// - Key derivation (seed -> private key -> public key -> address)
/// - Transaction construction
/// - Signature generation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestVector {
    /// Description of this test case
    pub description: String,

    /// BIP44 account index used for key derivation
    ///
    /// The full derivation path is: m/44'/12586'/account'/0/0
    pub account: u32,

    /// The seed used for BIP32 key derivation (hex-encoded)
    ///
    /// This is the input to the HMAC-SHA512 with "Bitcoin seed"
    pub seed: String,

    /// The derived private key (hex-encoded, little-endian)
    ///
    /// After BIP32 derivation and bit masking, this is the scalar
    /// value used for signing.
    pub private_key: String,

    /// The public key derived from the private key
    pub public_key: PublicKeyJson,

    /// The Mina address (B62...) derived from the public key
    pub address: String,

    /// Network identifier (0 = testnet, 1 = mainnet)
    pub network_id: u8,

    /// The transaction being signed
    pub transaction: TransactionJson,

    /// The resulting signature
    pub signature: SignatureJson,
}

/// Collection of test vectors
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestVectors {
    /// Version of the test vector format
    pub version: String,

    /// Description of the test vectors
    pub description: String,

    /// The test vectors
    pub test_vectors: Vec<TestVector>,
}

impl TestVectors {
    /// Create a new empty test vector collection
    pub fn new() -> Self {
        TestVectors {
            version: "1.0.0".to_string(),
            description: "Mina Ledger signing test vectors".to_string(),
            test_vectors: Vec::new(),
        }
    }

    /// Add a test vector to the collection
    pub fn add(&mut self, vector: TestVector) {
        self.test_vectors.push(vector);
    }
}

impl Default for TestVectors {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a single test vector for a payment transaction
///
/// # Parameters
///
/// * `seed` - The BIP32 seed bytes
/// * `account` - The BIP44 account index
/// * `network_id` - The network (mainnet or testnet)
/// * `receiver` - The receiver's public key
/// * `amount` - The payment amount in nanomina
/// * `fee` - The transaction fee in nanomina
/// * `nonce` - The sender's account nonce
/// * `valid_until` - Optional valid_until slot
/// * `memo` - Optional memo string
/// * `description` - Description for this test case
///
/// # Returns
///
/// A complete test vector with all derived values and signature
#[allow(clippy::too_many_arguments)]
pub fn generate_payment_vector(
    seed: &[u8],
    account: u32,
    network_id: NetworkId,
    receiver: &PubKey,
    amount: u64,
    fee: u64,
    nonce: u32,
    valid_until: Option<u32>,
    memo: &str,
    description: &str,
) -> TestVector {
    // Derive the keypair using BIP32
    let extended_key = ExtendedPrivateKey::derive_mina_path(seed, account);
    let secret_scalar = extended_key.to_mina_secret_key();
    let secret_key = SecKey::new(secret_scalar);
    let keypair = Keypair::from_secret_key(secret_key).expect("Failed to create keypair");

    // Create the transaction
    let mut tx =
        Transaction::new_payment(keypair.public.clone(), receiver.clone(), amount, fee, nonce);

    if let Some(slot) = valid_until {
        tx = tx.set_valid_until(slot);
    }

    if !memo.is_empty() {
        tx = tx.set_memo_str(memo);
    }

    // Sign the transaction using the legacy signer (compatible with Ledger)
    let mut signer = mina_signer::create_legacy::<Transaction>(network_id.clone());
    let signature = signer.sign(&keypair, &tx, true);

    // Verify the signature is valid
    assert!(
        signer.verify(&signature, &keypair.public, &tx),
        "Generated signature failed verification"
    );

    // Build the test vector
    TestVector {
        description: description.to_string(),
        account,
        seed: hex::encode(seed),
        private_key: secret_scalar.to_hex(),
        public_key: PublicKeyJson {
            x: keypair.public.point().x.to_hex(),
            y: keypair.public.point().y.to_hex(),
        },
        address: keypair.get_address(),
        network_id: network_id.clone() as u8,
        transaction: TransactionJson::payment(
            &receiver.into_address(),
            amount,
            fee,
            nonce,
            valid_until,
            memo,
        ),
        signature: SignatureJson {
            rx: signature.rx.to_hex(),
            s: signature.s.to_hex(),
        },
    }
}

/// Generate a single test vector for a delegation transaction
///
/// # Parameters
///
/// * `seed` - The BIP32 seed bytes
/// * `account` - The BIP44 account index
/// * `network_id` - The network (mainnet or testnet)
/// * `delegate_to` - The public key to delegate to
/// * `fee` - The transaction fee in nanomina
/// * `nonce` - The sender's account nonce
/// * `valid_until` - Optional valid_until slot
/// * `memo` - Optional memo string
/// * `description` - Description for this test case
///
/// # Returns
///
/// A complete test vector with all derived values and signature
#[allow(clippy::too_many_arguments)]
pub fn generate_delegation_vector(
    seed: &[u8],
    account: u32,
    network_id: NetworkId,
    delegate_to: &PubKey,
    fee: u64,
    nonce: u32,
    valid_until: Option<u32>,
    memo: &str,
    description: &str,
) -> TestVector {
    // Derive the keypair using BIP32
    let extended_key = ExtendedPrivateKey::derive_mina_path(seed, account);
    let secret_scalar = extended_key.to_mina_secret_key();
    let secret_key = SecKey::new(secret_scalar);
    let keypair = Keypair::from_secret_key(secret_key).expect("Failed to create keypair");

    // Create the delegation transaction
    let mut tx =
        Transaction::new_delegation(keypair.public.clone(), delegate_to.clone(), fee, nonce);

    if let Some(slot) = valid_until {
        tx = tx.set_valid_until(slot);
    }

    if !memo.is_empty() {
        tx = tx.set_memo_str(memo);
    }

    // Sign the transaction using the legacy signer
    let mut signer = mina_signer::create_legacy::<Transaction>(network_id.clone());
    let signature = signer.sign(&keypair, &tx, true);

    // Verify the signature is valid
    assert!(
        signer.verify(&signature, &keypair.public, &tx),
        "Generated signature failed verification"
    );

    // Build the test vector
    TestVector {
        description: description.to_string(),
        account,
        seed: hex::encode(seed),
        private_key: secret_scalar.to_hex(),
        public_key: PublicKeyJson {
            x: keypair.public.point().x.to_hex(),
            y: keypair.public.point().y.to_hex(),
        },
        address: keypair.get_address(),
        network_id: network_id.clone() as u8,
        transaction: TransactionJson::delegation(
            &delegate_to.into_address(),
            fee,
            nonce,
            valid_until,
            memo,
        ),
        signature: SignatureJson {
            rx: signature.rx.to_hex(),
            s: signature.s.to_hex(),
        },
    }
}

/// Generate a comprehensive set of test vectors
///
/// This function generates test vectors covering:
/// - Account indices 0, 1, 2
/// - Both mainnet and testnet
/// - Payment transactions with various amounts
/// - Delegation transactions
/// - Transactions with and without memos
/// - Different valid_until values
///
/// # Parameters
///
/// * `seed` - The BIP32 seed (32 bytes recommended)
///
/// # Returns
///
/// A collection of test vectors
pub fn generate_all_vectors(seed: &[u8]) -> TestVectors {
    let mut vectors = TestVectors::new();

    // Generate a receiver keypair for transactions
    // We use a deterministic key for reproducibility
    let receiver_seed = [1u8; 32];
    let receiver_extended = ExtendedPrivateKey::derive_mina_path(&receiver_seed, 0);
    let receiver_scalar = receiver_extended.to_mina_secret_key();
    let receiver_secret = SecKey::new(receiver_scalar);
    let receiver_kp = Keypair::from_secret_key(receiver_secret).expect("Failed to create keypair");
    let receiver = receiver_kp.public;

    // Test vector 1: Basic mainnet payment, account 0
    vectors.add(generate_payment_vector(
        seed,
        0,
        NetworkId::MAINNET,
        &receiver,
        1_000_000_000, // 1 MINA
        10_000_000,    // 0.01 MINA fee
        0,
        None,
        "",
        "Basic mainnet payment from account 0",
    ));

    // Test vector 2: Mainnet payment with memo, account 0
    vectors.add(generate_payment_vector(
        seed,
        0,
        NetworkId::MAINNET,
        &receiver,
        5_000_000_000, // 5 MINA
        20_000_000,    // 0.02 MINA fee
        1,
        Some(1000000),
        "Hello Mina!",
        "Mainnet payment with memo and valid_until",
    ));

    // Test vector 3: Testnet payment, account 0
    vectors.add(generate_payment_vector(
        seed,
        0,
        NetworkId::TESTNET,
        &receiver,
        2_500_000_000, // 2.5 MINA
        5_000_000,     // 0.005 MINA fee
        2,
        None,
        "",
        "Testnet payment from account 0",
    ));

    // Test vector 4: Mainnet payment, account 1 (different key)
    vectors.add(generate_payment_vector(
        seed,
        1,
        NetworkId::MAINNET,
        &receiver,
        100_000_000_000, // 100 MINA
        50_000_000,      // 0.05 MINA fee
        0,
        None,
        "",
        "Mainnet payment from account 1",
    ));

    // Test vector 5: Mainnet payment, account 2
    vectors.add(generate_payment_vector(
        seed,
        2,
        NetworkId::MAINNET,
        &receiver,
        1, // Minimum amount (1 nanomina)
        100_000_000,
        0,
        Some(u32::MAX),
        "",
        "Mainnet payment with minimum amount from account 2",
    ));

    // Test vector 6: Mainnet delegation, account 0
    vectors.add(generate_delegation_vector(
        seed,
        0,
        NetworkId::MAINNET,
        &receiver,
        10_000_000, // 0.01 MINA fee
        3,
        None,
        "",
        "Mainnet delegation from account 0",
    ));

    // Test vector 7: Mainnet delegation with memo, account 0
    vectors.add(generate_delegation_vector(
        seed,
        0,
        NetworkId::MAINNET,
        &receiver,
        20_000_000,
        4,
        Some(500000),
        "Delegate to validator",
        "Mainnet delegation with memo and valid_until",
    ));

    // Test vector 8: Testnet delegation, account 1
    vectors.add(generate_delegation_vector(
        seed,
        1,
        NetworkId::TESTNET,
        &receiver,
        5_000_000,
        0,
        None,
        "",
        "Testnet delegation from account 1",
    ));

    // Test vector 9: Large payment amount
    vectors.add(generate_payment_vector(
        seed,
        0,
        NetworkId::MAINNET,
        &receiver,
        1_000_000_000_000_000, // 1 billion MINA (theoretical max)
        1_000_000_000,
        5,
        None,
        "",
        "Mainnet payment with large amount",
    ));

    // Test vector 10: Long memo (32 chars, max length)
    vectors.add(generate_payment_vector(
        seed,
        0,
        NetworkId::MAINNET,
        &receiver,
        50_000_000_000,
        25_000_000,
        6,
        Some(271828),
        "01234567890123456789012345678901",
        "Mainnet payment with maximum length memo",
    ));

    vectors
}
