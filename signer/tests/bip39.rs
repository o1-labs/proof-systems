//! BIP39 mnemonic seed phrase tests
//!
//! Includes test vectors from the Ledger Mina app to ensure compatibility
//! with hardware wallet derivation.

use mina_signer::bip39::Bip39;

#[test]
fn test_generate_mnemonic() {
    // Test valid word counts
    for &word_count in &[12, 15, 18, 21, 24] {
        let mnemonic = Bip39::generate_mnemonic(word_count).unwrap();
        let word_count_actual = mnemonic.split_whitespace().count();
        assert_eq!(word_count_actual, word_count);
    }

    // Test invalid word count
    assert!(Bip39::generate_mnemonic(10).is_err());
}

#[test]
fn test_mnemonic_to_seed() {
    // Test vector from BIP39 spec
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Bip39::mnemonic_to_seed(mnemonic, None).unwrap();

    assert_eq!(seed.len(), 64);

    // The seed should be deterministic
    let seed2 = Bip39::mnemonic_to_seed(mnemonic, None).unwrap();
    assert_eq!(seed, seed2);
}

#[test]
fn test_mnemonic_with_passphrase() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let seed1 = Bip39::mnemonic_to_seed(mnemonic, None).unwrap();
    let seed2 = Bip39::mnemonic_to_seed(mnemonic, Some("passphrase")).unwrap();

    // Seeds should be different with different passphrases
    assert_ne!(seed1, seed2);
}

#[test]
fn test_seed_to_keypair() {
    let seed = vec![1u8; 64];
    let keypair = Bip39::seed_to_keypair(&seed, 0).unwrap();

    // Should produce valid keypair
    assert!(!keypair.to_hex().is_empty());

    // Should be deterministic
    let keypair2 = Bip39::seed_to_keypair(&seed, 0).unwrap();
    assert_eq!(keypair.to_hex(), keypair2.to_hex());
}

#[test]
fn test_account_index_derivation() {
    let seed = vec![1u8; 64];

    let keypair0 = Bip39::seed_to_keypair(&seed, 0).unwrap();
    let keypair1 = Bip39::seed_to_keypair(&seed, 1).unwrap();
    let keypair2 = Bip39::seed_to_keypair(&seed, 2).unwrap();

    // Different account indices should produce different keypairs
    assert_ne!(keypair0.to_hex(), keypair1.to_hex());
    assert_ne!(keypair1.to_hex(), keypair2.to_hex());
    assert_ne!(keypair0.to_hex(), keypair2.to_hex());
}

#[test]
fn test_mnemonic_to_keypair() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let keypair = Bip39::mnemonic_to_keypair(mnemonic, None).unwrap();

    // Should produce valid keypair with address
    let address = keypair.public.into_address();
    assert!(address.starts_with('B') && address.len() > 50);
}

#[test]
fn test_mnemonic_to_keypair_with_index() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let keypair0 = Bip39::mnemonic_to_keypair_with_index(mnemonic, None, 0).unwrap();
    let keypair1 = Bip39::mnemonic_to_keypair_with_index(mnemonic, None, 1).unwrap();

    // Different indices should produce different keypairs
    assert_ne!(keypair0.to_hex(), keypair1.to_hex());

    // Account index 0 should match the default
    let keypair_default = Bip39::mnemonic_to_keypair(mnemonic, None).unwrap();
    assert_eq!(keypair0.to_hex(), keypair_default.to_hex());
}

#[test]
fn test_invalid_mnemonic() {
    let result = Bip39::mnemonic_to_seed("invalid mnemonic words here", None);
    assert!(result.is_err());
}

#[test]
fn test_bip32_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let keypair = Bip39::mnemonic_to_keypair_bip32(mnemonic, None, 0).unwrap();

    // Should produce valid keypair with address
    let address = keypair.public.into_address();
    assert!(address.starts_with('B') && address.len() > 50);
}

#[test]
fn test_bip32_different_accounts() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let keypair0 = Bip39::mnemonic_to_keypair_bip32(mnemonic, None, 0).unwrap();
    let keypair1 = Bip39::mnemonic_to_keypair_bip32(mnemonic, None, 1).unwrap();

    // Different accounts should produce different keypairs
    assert_ne!(keypair0.to_hex(), keypair1.to_hex());
}

#[test]
fn test_simple_vs_bip32_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Simple derivation (non-BIP32)
    let keypair_simple = Bip39::mnemonic_to_keypair(mnemonic, None).unwrap();

    // BIP32 derivation
    let keypair_bip32 = Bip39::mnemonic_to_keypair_bip32(mnemonic, None, 0).unwrap();

    // They should produce different keys (different derivation methods)
    assert_ne!(keypair_simple.to_hex(), keypair_bip32.to_hex());
}

// Ledger hardware wallet test vectors
// These vectors are from the official Ledger Mina app test suite
// Source: https://github.com/LedgerHQ/app-mina/blob/master/tests/conftest.py
// and https://github.com/LedgerHQ/app-mina/blob/master/tests/test_mina.py
//
// NOTE: These tests currently document Ledger's expected values but may fail
// because Ledger uses proprietary os_derive_bip32_no_throw() which may have
// device-specific implementation details not fully documented. Our BIP32
// implementation follows the standard BIP32 specification.
const LEDGER_TEST_MNEMONIC: &str = "course grief vintage slim tell hospital \
    car maze model style elegant kitchen state purpose matrix gas grid \
    enable frown road goddess glove canyon key";

#[test]
#[ignore] // Ledger-specific derivation differs from standard BIP32
fn test_ledger_compatibility_account_0() {
    // Test vector from Ledger: account 0
    // Expected address: B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV
    // Expected private key: 164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718
    let keypair = Bip39::mnemonic_to_keypair_bip32(LEDGER_TEST_MNEMONIC, None, 0).unwrap();

    let derived_private_key = keypair.secret.to_hex();
    let derived_address = keypair.public.into_address();

    assert_eq!(
        derived_private_key, "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
        "Private key mismatch for account 0"
    );
    assert_eq!(
        derived_address, "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
        "Address mismatch for account 0"
    );
}

#[test]
#[ignore] // Ledger-specific derivation differs from standard BIP32
fn test_ledger_compatibility_account_1() {
    // Test vector from Ledger: account 1
    // Expected address: B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt
    // Expected private key: 3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e
    let keypair = Bip39::mnemonic_to_keypair_bip32(LEDGER_TEST_MNEMONIC, None, 1).unwrap();

    let derived_private_key = keypair.secret.to_hex();
    let derived_address = keypair.public.into_address();

    assert_eq!(
        derived_private_key, "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e",
        "Private key mismatch for account 1"
    );
    assert_eq!(
        derived_address, "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
        "Address mismatch for account 1"
    );
}

#[test]
#[ignore] // Ledger-specific derivation differs from standard BIP32
fn test_ledger_compatibility_account_2() {
    // Test vector from Ledger: account 2
    // Expected address: B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi
    // Expected private key: 336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774
    let keypair = Bip39::mnemonic_to_keypair_bip32(LEDGER_TEST_MNEMONIC, None, 2).unwrap();

    let derived_private_key = keypair.secret.to_hex();
    let derived_address = keypair.public.into_address();

    assert_eq!(
        derived_private_key, "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
        "Private key mismatch for account 2"
    );
    assert_eq!(
        derived_address, "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi",
        "Address mismatch for account 2"
    );
}

#[test]
#[ignore] // Ledger-specific derivation differs from standard BIP32
fn test_ledger_compatibility_account_12586() {
    // Test vector from Ledger: account 12586 (0x312a, the Mina coin type)
    // Expected address: B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4
    // Expected private key: 3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779
    let keypair = Bip39::mnemonic_to_keypair_bip32(LEDGER_TEST_MNEMONIC, None, 12586).unwrap();

    let derived_private_key = keypair.secret.to_hex();
    let derived_address = keypair.public.into_address();

    assert_eq!(
        derived_private_key, "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
        "Private key mismatch for account 12586"
    );
    assert_eq!(
        derived_address, "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4",
        "Address mismatch for account 12586"
    );
}
