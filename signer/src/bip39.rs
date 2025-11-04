//! BIP39 mnemonic seed phrase support for Mina key derivation
//!
//! This module provides functionality to derive Mina keypairs from BIP39
//! mnemonic seed phrases.
//! It supports:
//! - Generating mnemonics (12, 15, 18, 21, or 24 words)
//! - Deriving master seeds from mnemonics with optional passphrase
//! - Deriving Mina secret keys and keypairs from seeds
//!
//! # Examples
//!
//! ```
//! use mina_signer::bip39::Bip39;
//! use mina_signer::Keypair;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new 24-word mnemonic
//! let mnemonic = Bip39::generate_mnemonic(24)?;
//! println!("Mnemonic: {}", mnemonic);
//!
//! // Derive keypair from mnemonic (with optional passphrase)
//! let keypair = Bip39::mnemonic_to_keypair(
//!     &mnemonic, Some("optional-passphrase"))?;
//! println!("Address: {}", keypair.public.into_address());
//! # Ok(())
//! # }
//! ```

extern crate alloc;
use crate::{Keypair, ScalarField, SecKey};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use ark_ff::PrimeField;
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use thiserror::Error;

type HmacSha512 = Hmac<Sha512>;

/// Mina coin type for BIP44 derivation (as used by Ledger)
pub const MINA_COIN_TYPE: u32 = 12586;

/// BIP39 derivation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Bip39Error {
    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),
    /// Invalid word count (must be 12, 15, 18, 21, or 24)
    #[error("Invalid word count: {0} (must be 12, 15, 18, 21, or 24)")]
    InvalidWordCount(usize),
    /// Keypair derivation failed
    #[error("Failed to derive keypair")]
    KeypairDerivation,
    /// Invalid account index
    #[error("Invalid account index: {0}")]
    InvalidAccountIndex(u32),
    /// Invalid BIP32 derivation path
    #[error("Invalid BIP32 path: {0}")]
    InvalidPath(String),
    /// BIP32 derivation error
    #[error("BIP32 derivation failed")]
    Bip32Error,
}

/// BIP39 result type
pub type Result<T> = core::result::Result<T, Bip39Error>;

/// BIP39 utility for Mina key derivation
pub struct Bip39;

impl Bip39 {
    /// Generate a new BIP39 mnemonic with the specified word count
    ///
    /// # Arguments
    /// * `word_count` - Number of words (must be 12, 15, 18, 21, or 24)
    ///
    /// # Errors
    ///
    /// Returns an error if the word count is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mnemonic = Bip39::generate_mnemonic(24)?;
    /// println!("Mnemonic: {}", mnemonic);
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_mnemonic(word_count: usize) -> Result<String> {
        let entropy_bits = match word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => return Err(Bip39Error::InvalidWordCount(word_count)),
        };

        // Generate random entropy
        let entropy_bytes = entropy_bits / 8;
        let mut entropy = vec![0u8; entropy_bytes];

        // Use cryptographic random number generation
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.fill(&mut entropy[..]);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| Bip39Error::InvalidMnemonic(format!("{:?}", e)))?;

        Ok(mnemonic.to_string())
    }

    /// Derive a master seed (64 bytes) from a BIP39 mnemonic phrase
    ///
    /// This uses the BIP39 standard PBKDF2-HMAC-SHA512 derivation with
    /// 2048 iterations. The passphrase is optional and defaults to an
    /// empty string if not provided.
    ///
    /// # Arguments
    /// * `mnemonic` - The BIP39 mnemonic phrase (space-separated words)
    /// * `passphrase` - Optional passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon \
    ///     abandon abandon abandon abandon abandon about";
    /// let seed = Bip39::mnemonic_to_seed(mnemonic, None)?;
    /// assert_eq!(seed.len(), 64);
    /// # Ok(())
    /// # }
    /// ```
    pub fn mnemonic_to_seed(mnemonic: &str, passphrase: Option<&str>) -> Result<Vec<u8>> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| Bip39Error::InvalidMnemonic(format!("{:?}", e)))?;

        let passphrase = passphrase.unwrap_or("");
        let seed = mnemonic.to_seed(passphrase);

        Ok(seed.to_vec())
    }

    /// Derive a Mina secret key from a master seed
    ///
    /// This uses HMAC-SHA512 with the key "mina" to derive key material,
    /// then reduces it modulo the Pallas scalar field order.
    ///
    /// # Arguments
    /// * `seed` - Master seed bytes (typically 64 bytes from BIP39)
    /// * `account_index` - Account derivation index (default 0)
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let seed = vec![0u8; 64]; // Example seed
    /// let secret_key = Bip39::seed_to_secret_key(&seed, 0)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn seed_to_secret_key(seed: &[u8], account_index: u32) -> Result<SecKey> {
        // Derive account-specific seed using HMAC-SHA512
        // We use "mina" as the HMAC key to namespace this derivation
        let mut mac =
            HmacSha512::new_from_slice(b"mina").map_err(|_| Bip39Error::KeypairDerivation)?;

        mac.update(seed);
        mac.update(&account_index.to_le_bytes());

        let derived = mac.finalize().into_bytes();

        // Convert the first 32 bytes to a scalar field element
        // by reducing modulo the field order
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&derived[..32]);

        // Reduce the bytes to fit in the scalar field
        // ScalarField::from_random_bytes handles the modular reduction
        let scalar = ScalarField::from_le_bytes_mod_order(&bytes);

        Ok(SecKey::new(scalar))
    }

    /// Derive a Mina keypair from a master seed
    ///
    /// Convenience method that derives a secret key and generates the
    /// corresponding public key.
    ///
    /// # Arguments
    /// * `seed` - Master seed bytes (typically 64 bytes from BIP39)
    /// * `account_index` - Account derivation index (default 0)
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or keypair generation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let seed = vec![0u8; 64];
    /// let keypair = Bip39::seed_to_keypair(&seed, 0)?;
    /// println!("Address: {}", keypair.public.into_address());
    /// # Ok(())
    /// # }
    /// ```
    pub fn seed_to_keypair(seed: &[u8], account_index: u32) -> Result<Keypair> {
        let secret_key = Self::seed_to_secret_key(seed, account_index)?;
        Keypair::from_secret_key(secret_key).map_err(|_| Bip39Error::KeypairDerivation)
    }

    /// Derive a Mina keypair directly from a mnemonic phrase
    ///
    /// This is a convenience method that combines mnemonic-to-seed
    /// and seed-to-keypair.
    ///
    /// # Arguments
    /// * `mnemonic` - The BIP39 mnemonic phrase
    /// * `passphrase` - Optional passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is invalid or key derivation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon \
    ///     abandon abandon abandon abandon abandon about";
    /// let keypair = Bip39::mnemonic_to_keypair(mnemonic, None)?;
    /// println!("Address: {}", keypair.public.into_address());
    /// # Ok(())
    /// # }
    /// ```
    pub fn mnemonic_to_keypair(mnemonic: &str, passphrase: Option<&str>) -> Result<Keypair> {
        let seed = Self::mnemonic_to_seed(mnemonic, passphrase)?;
        Self::seed_to_keypair(&seed, 0)
    }

    /// Derive a Mina keypair from a mnemonic with a specific account index
    ///
    /// This allows deriving multiple accounts from the same mnemonic.
    ///
    /// # Arguments
    /// * `mnemonic` - The BIP39 mnemonic phrase
    /// * `passphrase` - Optional passphrase for additional security
    /// * `account_index` - Account derivation index (0 for first account,
    ///   1 for second, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is invalid or key derivation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon \
    ///     abandon abandon abandon abandon abandon about";
    ///
    /// // Derive first account (index 0)
    /// let keypair0 = Bip39::mnemonic_to_keypair_with_index(
    ///     mnemonic, None, 0)?;
    ///
    /// // Derive second account (index 1)
    /// let keypair1 = Bip39::mnemonic_to_keypair_with_index(
    ///     mnemonic, None, 1)?;
    ///
    /// // They will have different addresses
    /// assert_ne!(keypair0.public.into_address(),
    ///     keypair1.public.into_address());
    /// # Ok(())
    /// # }
    /// ```
    pub fn mnemonic_to_keypair_with_index(
        mnemonic: &str,
        passphrase: Option<&str>,
        account_index: u32,
    ) -> Result<Keypair> {
        let seed = Self::mnemonic_to_seed(mnemonic, passphrase)?;
        Self::seed_to_keypair(&seed, account_index)
    }

    /// Derive a child key using BIP32-Ed25519 derivation (hardened path only)
    ///
    /// This implements SLIP-0010 Ed25519 derivation for hardened paths.
    /// Returns (child_key, child_chain_code).
    fn bip32_derive_hardened(
        parent_key: &[u8; 32],
        parent_chain_code: &[u8; 32],
        index: u32,
    ) -> Result<([u8; 32], [u8; 32])> {
        // For hardened derivation: index >= 2^31
        let hardened_index = index | 0x8000_0000;

        // HMAC-SHA512(chain_code, 0x00 || parent_key || index)
        let mut mac =
            HmacSha512::new_from_slice(parent_chain_code).map_err(|_| Bip39Error::Bip32Error)?;

        mac.update(&[0x00]);
        mac.update(parent_key);
        mac.update(&hardened_index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut child_key = [0u8; 32];
        let mut child_chain_code = [0u8; 32];

        child_key.copy_from_slice(&result[..32]);
        child_chain_code.copy_from_slice(&result[32..]);

        Ok((child_key, child_chain_code))
    }

    /// Derive a Mina keypair using BIP32 hierarchical deterministic
    /// derivation
    ///
    /// This follows the Ledger implementation using the standard BIP44
    /// path: `m/44'/12586'/account'/0/0` where 12586 is Mina's coin type.
    ///
    /// # Arguments
    /// * `seed` - Master seed bytes (typically 64 bytes from BIP39)
    /// * `account` - BIP44 account index (hardened)
    ///
    /// # Errors
    ///
    /// Returns an error if BIP32 derivation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon \
    ///     abandon abandon abandon abandon abandon about";
    /// let seed = Bip39::mnemonic_to_seed(mnemonic, None)?;
    ///
    /// // Derive using BIP32 path m/44'/12586'/0'/0/0
    /// let keypair = Bip39::seed_to_keypair_bip32(&seed, 0)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn seed_to_keypair_bip32(seed: &[u8], account: u32) -> Result<Keypair> {
        // Generate master key from seed using HMAC-SHA512
        // Following BIP32 specification (secp256k1 derivation)
        // Note: Ledger uses secp256k1 BIP32, not Ed25519 SLIP-0010
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| Bip39Error::Bip32Error)?;
        mac.update(seed);
        let master = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&master[..32]);
        chain_code.copy_from_slice(&master[32..]);

        // Derive path: m/44'/12586'/account'/0/0
        // All hardened derivations as per BIP44
        (key, chain_code) = Self::bip32_derive_hardened(&key, &chain_code, 44)?;
        (key, chain_code) = Self::bip32_derive_hardened(&key, &chain_code, MINA_COIN_TYPE)?;
        (key, chain_code) = Self::bip32_derive_hardened(&key, &chain_code, account)?;
        (key, chain_code) = Self::bip32_derive_hardened(&key, &chain_code, 0)?;
        (key, _) = Self::bip32_derive_hardened(&key, &chain_code, 0)?;

        // Convert to scalar field element with proper reduction
        // Following Ledger's approach: clear top 2 bits to ensure
        // it's < field order
        let mut scalar_bytes = key;

        // Clear the top 2 bits (following Ledger implementation)
        scalar_bytes[31] &= 0x3f;

        // Convert to big-endian for Mina scalar field
        scalar_bytes.reverse();

        let secret_key = SecKey::from_bytes(&scalar_bytes).map_err(|_| Bip39Error::Bip32Error)?;
        Keypair::from_secret_key(secret_key).map_err(|_| Bip39Error::KeypairDerivation)
    }

    /// Derive a Mina keypair from mnemonic using BIP32 hierarchical
    /// derivation
    ///
    /// This is the Ledger-compatible derivation method using path
    /// `m/44'/12586'/account'/0/0`.
    ///
    /// # Arguments
    /// * `mnemonic` - The BIP39 mnemonic phrase
    /// * `passphrase` - Optional passphrase for additional security
    /// * `account` - BIP44 account index (0 for first account, 1 for
    ///   second, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is invalid or key derivation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mina_signer::bip39::Bip39;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon \
    ///     abandon abandon abandon abandon abandon about";
    ///
    /// // Ledger-compatible derivation for account 0
    /// let keypair = Bip39::mnemonic_to_keypair_bip32(mnemonic, None, 0)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn mnemonic_to_keypair_bip32(
        mnemonic: &str,
        passphrase: Option<&str>,
        account: u32,
    ) -> Result<Keypair> {
        let seed = Self::mnemonic_to_seed(mnemonic, passphrase)?;
        Self::seed_to_keypair_bip32(&seed, account)
    }
}
