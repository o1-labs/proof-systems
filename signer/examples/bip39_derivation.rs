//! Comprehensive example of BIP39 mnemonic seed phrase support for Mina
//!
//! This example demonstrates:
//! 1. Generating BIP39 mnemonic phrases
//! 2. Deriving Mina keypairs from mnemonics
//! 3. Using BIP32 hierarchical deterministic derivation (Ledger-compatible)
//! 4. Deriving multiple accounts from a single mnemonic
//!
//! Run with:
//! ```
//! cargo run --example bip39_derivation
//! ```

use mina_signer::bip39::{Bip39, MINA_COIN_TYPE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Mina BIP39 Derivation Example ===\n");

    // Example 1: Generate a new mnemonic
    println!("1. Generate a new 24-word mnemonic:");
    let mnemonic = Bip39::generate_mnemonic(24)?;
    println!("   Mnemonic: {}\n", mnemonic);

    // Example 2: Use a known test mnemonic
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    println!("2. Using test mnemonic for reproducible results:");
    println!("   Mnemonic: {}\n", test_mnemonic);

    // Example 3: Simple derivation (non-BIP32)
    println!("3. Simple derivation (non-BIP32 hierarchical):");
    let keypair_simple = Bip39::mnemonic_to_keypair(test_mnemonic, None)?;
    println!("   Secret key: {}", keypair_simple.secret.to_hex());
    println!("   Address: {}\n", keypair_simple.public.into_address());

    // Example 4: BIP32 hierarchical derivation (Ledger-compatible)
    println!("4. BIP32 hierarchical derivation (Ledger-compatible):");
    println!("   Path: m/44'/{}'/<account>'/0/0", MINA_COIN_TYPE);
    let keypair_bip32 = Bip39::mnemonic_to_keypair_bip32(test_mnemonic, None, 0)?;
    println!("   Account 0:");
    println!("     Secret key: {}", keypair_bip32.secret.to_hex());
    println!("     Address: {}\n", keypair_bip32.public.into_address());

    // Example 5: Multiple accounts from the same mnemonic
    println!("5. Derive multiple accounts (BIP32 HD wallet):");
    for account in 0..3 {
        let keypair = Bip39::mnemonic_to_keypair_bip32(test_mnemonic, None, account)?;
        println!("   Account {}: {}", account, keypair.public.into_address());
    }
    println!();

    // Example 6: Using a passphrase for additional security
    println!("6. Derivation with optional passphrase:");
    let keypair_no_pass = Bip39::mnemonic_to_keypair_bip32(test_mnemonic, None, 0)?;
    let keypair_with_pass =
        Bip39::mnemonic_to_keypair_bip32(test_mnemonic, Some("my-secret-passphrase"), 0)?;

    println!(
        "   Without passphrase: {}",
        keypair_no_pass.public.into_address()
    );
    println!(
        "   With passphrase:    {}",
        keypair_with_pass.public.into_address()
    );
    println!("   (Different passphrases produce different keys)\n");

    // Example 7: Working with seeds directly
    println!("7. Advanced: Working with seeds directly:");
    let seed = Bip39::mnemonic_to_seed(test_mnemonic, None)?;
    println!("   Seed length: {} bytes", seed.len());
    println!("   Seed (hex): {}...", hex::encode(&seed[..16]));

    // Derive from seed
    let keypair_from_seed = Bip39::seed_to_keypair_bip32(&seed, 0)?;
    println!(
        "   Derived address: {}\n",
        keypair_from_seed.public.into_address()
    );

    // Example 8: Non-BIP32 account indexing
    println!("8. Simple account indexing (non-BIP32):");
    for account_index in 0..3 {
        let keypair = Bip39::mnemonic_to_keypair_with_index(test_mnemonic, None, account_index)?;
        println!(
            "   Account {}: {}",
            account_index,
            keypair.public.into_address()
        );
    }

    println!("\n=== Best Practices ===");
    println!("1. Use BIP32 derivation (mnemonic_to_keypair_bip32) for Ledger compatibility");
    println!("2. Store mnemonics securely - they provide access to all derived accounts");
    println!("3. Use passphrases for an additional layer of security");
    println!("4. BIP44 path for Mina: m/44'/12586'/<account>'/0/0");
    println!("5. Never share your mnemonic or secret keys");

    Ok(())
}
