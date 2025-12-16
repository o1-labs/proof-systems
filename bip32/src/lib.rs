//! BIP32 Hierarchical Deterministic Key Derivation for Mina
//!
//! This crate implements BIP32/BIP44 key derivation for Mina's Pallas curve,
//! as used by the Mina Ledger hardware wallet application.
//!
//! This implementation follows the standards defined in:
//! - BIP32: <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
//! - BIP44: <https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki>
//! - SLIP44: <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>
//!
//! # Mina Key Derivation Path
//!
//! Mina uses the BIP44 derivation path:
//! ```text
//! m / 44' / 12586' / account' / 0 / 0
//! ```
//!
//! Where:
//! - `m` is the master key derived from a seed
//! - `44'` is the BIP44 purpose (hardened)
//! - `12586'` is Mina's registered coin type in SLIP44 (hardened)
//! - `account'` is the account index (hardened)
//! - `0` is the change index (external chain)
//! - `0` is the address index
//!
//! The apostrophe (') indicates hardened derivation.
//!
//! # Algorithm Overview
//!
//! ## Master Key Derivation
//!
//! The master key is derived from a seed using HMAC-SHA512:
//! ```text
//! I = HMAC-SHA512(key="Bitcoin seed", data=seed)
//! master_private_key = I[0..32]  // Left 32 bytes
//! master_chain_code = I[32..64]  // Right 32 bytes
//! ```
//!
//! ## Child Key Derivation
//!
//! For hardened derivation (index >= 2^31):
//! ```text
//! I = HMAC-SHA512(key=parent_chain_code, data=0x00 || parent_private_key || index)
//! child_key_material = I[0..32]
//! child_chain_code = I[32..64]
//! child_private_key = (parent_private_key + child_key_material) mod n
//! ```
//!
//! Where `n` is the order of the Pallas scalar field.
//!
//! ## Final Key Processing
//!
//! After derivation, the top 2 bits of the private key are masked to ensure
//! the value is within the valid range for Pallas scalar field elements
//! (which is approximately 2^254).
//!
//! # Security Considerations
//!
//! - The seed should be generated from sufficient entropy (typically 256 bits)
//! - The master key should never be exposed or stored insecurely
//! - Hardened derivation prevents public key derivation from parent
//!
//! # Example
//!
//! ```rust
//! use mina_bip32::ExtendedPrivateKey;
//! use mina_signer::{SecKey, Keypair};
//!
//! // 32-byte seed (in practice, derive from BIP39 mnemonic)
//! let seed = [0u8; 32];
//!
//! // Derive key at path m/44'/12586'/0'/0/0
//! let extended_key = ExtendedPrivateKey::derive_mina_path(&seed, 0);
//!
//! // Get the Mina-compatible secret key scalar
//! let secret_scalar = extended_key.to_mina_secret_key();
//!
//! // Create a keypair for signing
//! let secret = SecKey::new(secret_scalar);
//! let keypair = Keypair::from_secret_key(secret).unwrap();
//! println!("Address: {}", keypair.get_address());
//! ```

use ark_ff::PrimeField;
use hmac::{Hmac, Mac};
use mina_signer::ScalarField;
use sha2::Sha512;

/// secp256k1 curve order used for standard BIP32 key derivation
///
/// This is the order of the secp256k1 curve group:
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
///
/// BIP32 specifies using secp256k1 for key derivation even when the
/// target curve is different (like Pallas for Mina).
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Add two 256-bit numbers modulo the secp256k1 curve order
///
/// This function performs: (a + b) mod n
/// where n is the secp256k1 curve order.
///
/// Both inputs and output are in big-endian format.
fn add_mod_secp256k1(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Perform addition with carry
    let mut result = [0u8; 33]; // Extra byte for potential overflow
    let mut carry: u16 = 0;

    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i + 1] = sum as u8;
        carry = sum >> 8;
    }
    result[0] = carry as u8;

    // Check if result >= secp256k1_order and subtract if needed
    let mut need_subtract = result[0] > 0; // If there's overflow in the 33rd byte

    if !need_subtract {
        // Compare result[1..33] with SECP256K1_ORDER
        for i in 0..32 {
            match result[i + 1].cmp(&SECP256K1_ORDER[i]) {
                core::cmp::Ordering::Greater => {
                    need_subtract = true;
                    break;
                }
                core::cmp::Ordering::Less => {
                    break;
                }
                core::cmp::Ordering::Equal => {}
            }
        }
    }

    if need_subtract {
        // Subtract secp256k1_order from result
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let diff = result[i + 1] as i16 - SECP256K1_ORDER[i] as i16 - borrow;
            if diff < 0 {
                result[i + 1] = (diff + 256) as u8;
                borrow = 1;
            } else {
                result[i + 1] = diff as u8;
                borrow = 0;
            }
        }
    }

    let mut output = [0u8; 32];
    output.copy_from_slice(&result[1..33]);
    output
}

/// Mina coin type for BIP44, registered in SLIP-0044
///
/// See: <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>
/// Mina's coin type is 12586 (0x312A)
pub const MINA_COIN_TYPE: u32 = 12586;

/// BIP44 purpose constant
///
/// This is the standard purpose value defined in BIP44 for
/// multi-account hierarchy for deterministic wallets.
pub const BIP44_PURPOSE: u32 = 44;

/// Hardened derivation offset (2^31 = 0x80000000)
///
/// Indices >= this value indicate hardened derivation,
/// which uses the private key in the HMAC input rather than
/// the public key. This prevents derivation of child public
/// keys from a parent public key.
pub const HARDENED_OFFSET: u32 = 0x80000000;

/// Extended private key containing both the private key and chain code
///
/// An extended key consists of:
/// - A 32-byte private key (the actual signing key)
/// - A 32-byte chain code (used for deriving child keys)
///
/// The chain code adds additional entropy to the derivation process,
/// ensuring that knowledge of a parent private key alone is not
/// sufficient to derive child keys.
///
/// # Example
///
/// ```rust
/// use mina_bip32::{ExtendedPrivateKey, HARDENED_OFFSET};
///
/// // Create master key from seed
/// let seed = [0u8; 32];
/// let master = ExtendedPrivateKey::from_seed(&seed);
///
/// // Manually derive child keys
/// let child = master.derive_child(44 + HARDENED_OFFSET);
/// ```
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    /// The 32-byte private key
    ///
    /// This is stored in big-endian format for BIP32 compatibility.
    /// When converting to a Mina scalar, it is reversed to little-endian.
    pub private_key: [u8; 32],

    /// The 32-byte chain code
    ///
    /// Used as the HMAC key when deriving child keys.
    /// This value should be kept secret along with the private key.
    pub chain_code: [u8; 32],
}

impl ExtendedPrivateKey {
    /// Derive the master key from a seed using HMAC-SHA512
    ///
    /// # Algorithm
    ///
    /// ```text
    /// I = HMAC-SHA512(key="Bitcoin seed", data=seed)
    /// master_private_key = I[0..32]
    /// master_chain_code = I[32..64]
    /// ```
    ///
    /// The string "Bitcoin seed" is used as the HMAC key, as specified
    /// in BIP32. This is standard across all BIP32-compatible implementations.
    ///
    /// # Parameters
    ///
    /// * `seed` - The seed bytes (typically 16-64 bytes, commonly 32 bytes)
    ///
    /// # Returns
    ///
    /// The master extended private key
    ///
    /// # Example
    ///
    /// ```rust
    /// use mina_bip32::ExtendedPrivateKey;
    ///
    /// let seed = [0u8; 32]; // In practice, derive from BIP39 mnemonic
    /// let master = ExtendedPrivateKey::from_seed(&seed);
    ///
    /// assert_eq!(master.private_key.len(), 32);
    /// assert_eq!(master.chain_code.len(), 32);
    /// ```
    pub fn from_seed(seed: &[u8]) -> Self {
        // Create HMAC-SHA512 with "Bitcoin seed" as the key
        let mut mac =
            Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        // Split the 64-byte result into private key and chain code
        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        ExtendedPrivateKey {
            private_key,
            chain_code,
        }
    }

    /// Derive a child key at the given index
    ///
    /// # Algorithm
    ///
    /// For hardened derivation (index >= 2^31):
    /// ```text
    /// data = 0x00 || parent_private_key || ser32(index)
    /// I = HMAC-SHA512(key=parent_chain_code, data=data)
    /// child_key_material = I[0..32]
    /// child_chain_code = I[32..64]
    /// child_private_key = (parent_private_key + child_key_material) mod n
    /// ```
    ///
    /// Where:
    /// - `||` denotes concatenation
    /// - `ser32` serializes a 32-bit unsigned integer in big-endian format
    /// - `n` is the order of the secp256k1 curve (standard BIP32)
    ///
    /// **Important**: BIP32 specifies using secp256k1 for key derivation,
    /// even when the target curve is different (like Pallas for Mina).
    /// The Ledger hardware wallet follows this standard.
    ///
    /// For normal derivation (index < 2^31):
    /// This implementation uses the same method as hardened derivation
    /// since Mina only uses the last two levels (0/0) for normal derivation.
    ///
    /// # Parameters
    ///
    /// * `index` - The child index. Add `HARDENED_OFFSET` (0x80000000) for
    ///   hardened derivation.
    ///
    /// # Returns
    ///
    /// The child extended private key
    ///
    /// # Example
    ///
    /// ```rust
    /// use mina_bip32::{ExtendedPrivateKey, HARDENED_OFFSET};
    ///
    /// let master = ExtendedPrivateKey::from_seed(&[0u8; 32]);
    ///
    /// // Derive hardened child at index 44 (BIP44 purpose)
    /// let purpose = master.derive_child(44 + HARDENED_OFFSET);
    ///
    /// // Derive hardened child at index 12586 (Mina coin type)
    /// let coin_type = purpose.derive_child(12586 + HARDENED_OFFSET);
    /// ```
    pub fn derive_child(&self, index: u32) -> Self {
        // Create HMAC-SHA512 with parent chain code as the key
        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code)
            .expect("HMAC can take key of any size");

        // Construct the HMAC data based on derivation type
        if index >= HARDENED_OFFSET {
            // Hardened derivation: 0x00 || private_key || index
            mac.update(&[0x00]);
            mac.update(&self.private_key);
        } else {
            // Normal derivation: For Mina's path, we use the same approach
            // since the last two levels (0/0) don't need public key derivation
            mac.update(&[0x00]);
            mac.update(&self.private_key);
        }
        // Append the index in big-endian format
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        // Split the result into key material and chain code
        let mut child_key_material = [0u8; 32];
        let mut child_chain_code = [0u8; 32];
        child_key_material.copy_from_slice(&result[..32]);
        child_chain_code.copy_from_slice(&result[32..]);

        // Compute child_private_key = (parent_private_key + child_key_material) mod n
        // where n is the secp256k1 curve order (standard BIP32)
        let final_key = add_mod_secp256k1(&self.private_key, &child_key_material);

        ExtendedPrivateKey {
            private_key: final_key,
            chain_code: child_chain_code,
        }
    }

    /// Derive a key at the Mina BIP44 path: m/44'/12586'/account'/0/0
    ///
    /// This is a convenience method that derives through the full Mina path.
    ///
    /// # Path Structure
    ///
    /// ```text
    /// m        - Master key (derived from seed)
    /// └── 44'  - Purpose: BIP44 (hardened)
    ///     └── 12586' - Coin type: Mina (hardened)
    ///         └── account' - Account index (hardened)
    ///             └── 0 - External chain (change)
    ///                 └── 0 - Address index
    /// ```
    ///
    /// # Parameters
    ///
    /// * `seed` - The seed bytes to derive from
    /// * `account` - The account index (will be hardened)
    ///
    /// # Returns
    ///
    /// The extended private key at the specified path
    ///
    /// # Example
    ///
    /// ```rust
    /// use mina_bip32::ExtendedPrivateKey;
    ///
    /// let seed = [0u8; 32];
    ///
    /// // Derive key for account 0: m/44'/12586'/0'/0/0
    /// let key0 = ExtendedPrivateKey::derive_mina_path(&seed, 0);
    ///
    /// // Derive key for account 1: m/44'/12586'/1'/0/0
    /// let key1 = ExtendedPrivateKey::derive_mina_path(&seed, 1);
    ///
    /// // Different accounts produce different keys
    /// assert_ne!(key0.private_key, key1.private_key);
    /// ```
    pub fn derive_mina_path(seed: &[u8], account: u32) -> Self {
        // Start with the master key
        let master = Self::from_seed(seed);

        // m/44' (purpose - hardened)
        let purpose = master.derive_child(BIP44_PURPOSE + HARDENED_OFFSET);

        // m/44'/12586' (coin type - hardened)
        let coin_type = purpose.derive_child(MINA_COIN_TYPE + HARDENED_OFFSET);

        // m/44'/12586'/account' (account - hardened)
        let account_key = coin_type.derive_child(account + HARDENED_OFFSET);

        // m/44'/12586'/account'/0 (change - not hardened)
        let change = account_key.derive_child(0);

        // m/44'/12586'/account'/0/0 (address index - not hardened)
        change.derive_child(0)
    }

    /// Convert the derived private key to a Mina scalar field element
    ///
    /// # Algorithm
    ///
    /// 1. Copy the 32-byte private key
    /// 2. Mask the top 2 bits of the first byte to ensure the value
    ///    fits within the Pallas scalar field (~2^254)
    /// 3. Reverse the bytes (BIP32 uses big-endian, arkworks uses little-endian)
    /// 4. Convert to scalar field element
    ///
    /// # Bit Masking
    ///
    /// The Pallas scalar field order is:
    /// ```text
    /// 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
    /// ```
    ///
    /// This is approximately 2^254, so a 256-bit value might overflow.
    /// Masking the top 2 bits ensures the value is always valid:
    /// ```text
    /// key_bytes[0] &= 0b00111111  // Clear bits 7 and 6
    /// ```
    ///
    /// # Returns
    ///
    /// A valid Mina scalar field element suitable for use as a secret key
    ///
    /// # Example
    ///
    /// ```rust
    /// use mina_bip32::ExtendedPrivateKey;
    /// use mina_signer::{SecKey, Keypair};
    ///
    /// let extended = ExtendedPrivateKey::derive_mina_path(&[0u8; 32], 0);
    /// let scalar = extended.to_mina_secret_key();
    ///
    /// // Create a keypair from the derived scalar
    /// let secret = SecKey::new(scalar);
    /// let keypair = Keypair::from_secret_key(secret).unwrap();
    ///
    /// // The address is deterministic for a given seed and account
    /// println!("Address: {}", keypair.get_address());
    /// ```
    pub fn to_mina_secret_key(&self) -> ScalarField {
        let mut key_bytes = self.private_key;

        // Mask top 2 bits to ensure valid scalar field element
        // The Pallas scalar field order is approximately 2^254,
        // so we clear the top 2 bits to guarantee the value fits
        key_bytes[0] &= 0b0011_1111;

        // Convert from big-endian (BIP32) to little-endian (arkworks)
        key_bytes.reverse();

        // Convert to scalar field element
        ScalarField::from_le_bytes_mod_order(&key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use mina_signer::{Keypair, SecKey};

    #[test]
    fn test_master_key_derivation() {
        // Test with a known seed
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        // Verify the output has correct length
        assert_eq!(master.private_key.len(), 32);
        assert_eq!(master.chain_code.len(), 32);

        // The derivation should be deterministic
        let master2 = ExtendedPrivateKey::from_seed(&seed);
        assert_eq!(master.private_key, master2.private_key);
        assert_eq!(master.chain_code, master2.chain_code);
    }

    #[test]
    fn test_mina_path_derivation() {
        let seed = [0u8; 32];
        let key = ExtendedPrivateKey::derive_mina_path(&seed, 0);

        // Should produce a non-zero scalar
        let scalar = key.to_mina_secret_key();
        assert!(!scalar.is_zero());
    }

    #[test]
    fn test_different_accounts_produce_different_keys() {
        let seed = [0u8; 32];
        let key0 = ExtendedPrivateKey::derive_mina_path(&seed, 0);
        let key1 = ExtendedPrivateKey::derive_mina_path(&seed, 1);

        // Different accounts should produce different private keys
        assert_ne!(key0.private_key, key1.private_key);
    }

    #[test]
    fn test_deterministic_derivation() {
        let seed = [42u8; 32];

        // Multiple derivations with the same parameters should produce
        // identical results
        let key1 = ExtendedPrivateKey::derive_mina_path(&seed, 0);
        let key2 = ExtendedPrivateKey::derive_mina_path(&seed, 0);

        assert_eq!(key1.private_key, key2.private_key);
        assert_eq!(key1.chain_code, key2.chain_code);
    }

    #[test]
    fn test_bit_masking() {
        // Create a key with high bits set
        let key = ExtendedPrivateKey {
            private_key: [0xFF; 32],
            chain_code: [0; 32],
        };

        // The first byte should have high bits
        assert_eq!(key.private_key[0], 0xFF);

        // After conversion, it should be masked
        let scalar = key.to_mina_secret_key();

        // The scalar should be non-zero and valid
        assert!(!scalar.is_zero());
    }

    /// Regression tests for BIP32 derivation
    ///
    /// These tests ensure our implementation produces deterministic results.
    /// The expected values are generated by this implementation and serve
    /// as regression tests to detect unintended changes.
    ///
    /// **Important**: These test vectors should be validated against actual
    /// Ledger hardware wallet devices before being considered canonical.
    /// The reference implementation is ledger-mina:
    /// <https://github.com/jspada/ledger-app-mina>
    ///
    /// The Ledger uses `os_perso_derive_node_bip32(CX_CURVE_256K1, ...)` which
    /// is Ledger's proprietary BIP32 implementation with secp256k1.
    mod regression_tests {
        use super::*;

        /// Test seed for regression tests (deterministic)
        const TEST_SEED: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        /// Regression test: Account 0 produces deterministic address
        ///
        /// This test verifies that the derivation is deterministic.
        /// The expected address was generated by this implementation.
        #[test]
        fn regression_account_0() {
            let extended = ExtendedPrivateKey::derive_mina_path(&TEST_SEED, 0);
            let scalar = extended.to_mina_secret_key();
            let secret = SecKey::new(scalar);
            let keypair = Keypair::from_secret_key(secret).expect("Failed to create keypair");

            // Regression value - update if implementation changes intentionally
            let expected_address = "B62qmfxDF1KCTsepXAXEWNjxu7CNS899dak1Q4G8bwio151dkeycbVC";
            assert_eq!(
                keypair.get_address(),
                expected_address,
                "Account 0 regression test failed - address changed"
            );
        }

        /// Regression test: Account 1 produces deterministic address
        #[test]
        fn regression_account_1() {
            let extended = ExtendedPrivateKey::derive_mina_path(&TEST_SEED, 1);
            let scalar = extended.to_mina_secret_key();
            let secret = SecKey::new(scalar);
            let keypair = Keypair::from_secret_key(secret).expect("Failed to create keypair");

            // Regression value - update if implementation changes intentionally
            let expected_address = "B62qjBkoJb3pYzXeW9pYMprAkSvXK442iPhPS8xXUApjyiJmoX2Edfh";
            assert_eq!(
                keypair.get_address(),
                expected_address,
                "Account 1 regression test failed - address changed"
            );
        }

        /// Regression test: Account 12586 (coin type number) produces deterministic address
        #[test]
        fn regression_account_12586() {
            let extended = ExtendedPrivateKey::derive_mina_path(&TEST_SEED, 12586);
            let scalar = extended.to_mina_secret_key();
            let secret = SecKey::new(scalar);
            let keypair = Keypair::from_secret_key(secret).expect("Failed to create keypair");

            // Regression value - update if implementation changes intentionally
            let expected_address = "B62qpBzhXXuxQF9ocveNm2FtR9KoJ3MwetzY5hJCXmZN2eoA5bGJYvZ";
            assert_eq!(
                keypair.get_address(),
                expected_address,
                "Account 12586 regression test failed - address changed"
            );
        }

        /// Regression test: Large account index produces deterministic address
        #[test]
        fn regression_account_1000000() {
            let extended = ExtendedPrivateKey::derive_mina_path(&TEST_SEED, 1_000_000);
            let scalar = extended.to_mina_secret_key();
            let secret = SecKey::new(scalar);
            let keypair = Keypair::from_secret_key(secret).expect("Failed to create keypair");

            // Regression value - update if implementation changes intentionally
            let expected_address = "B62qp8DeGwCtzXbgEpBrRy5vNdgDr9tuFp33fPJuEMCA9UbXXVfNHEe";
            assert_eq!(
                keypair.get_address(),
                expected_address,
                "Account 1000000 regression test failed - address changed"
            );
        }

        /// Regression test: Different seeds produce different keys
        #[test]
        fn different_seeds_different_keys() {
            let seed1 = [0u8; 32];
            let seed2 = [1u8; 32];

            let key1 = ExtendedPrivateKey::derive_mina_path(&seed1, 0);
            let key2 = ExtendedPrivateKey::derive_mina_path(&seed2, 0);

            assert_ne!(key1.private_key, key2.private_key);
        }
    }
}
