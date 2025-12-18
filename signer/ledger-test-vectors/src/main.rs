//! Mina Ledger Test Vector Generator
//!
//! This binary generates JSON test vectors for validating Mina Ledger
//! hardware wallet signing implementations.
//!
//! # Usage
//!
//! ```bash
//! # Generate test vectors with default seed to stdout
//! cargo run --package ledger-test-vectors
//!
//! # Generate test vectors to a file
//! cargo run --package ledger-test-vectors -- -o test_vectors.json
//!
//! # Generate with custom seed
//! cargo run --package ledger-test-vectors -- --seed 0102030405...
//!
//! # Generate with verbose output
//! cargo run --package ledger-test-vectors -- -v
//! ```
//!
//! # Output Format
//!
//! The generated JSON follows this structure:
//!
//! ```json
//! {
//!   "version": "1.0.0",
//!   "description": "Mina Ledger signing test vectors",
//!   "test_vectors": [
//!     {
//!       "description": "Test case description",
//!       "account": 0,
//!       "seed": "hex-encoded seed",
//!       "private_key": "hex-encoded scalar",
//!       "public_key": { "x": "hex", "y": "hex" },
//!       "address": "B62...",
//!       "network_id": 1,
//!       "transaction": { ... },
//!       "signature": { "rx": "hex", "s": "hex" }
//!     }
//!   ]
//! }
//! ```
//!
//! # Validation
//!
//! To validate a Ledger implementation against these test vectors:
//!
//! 1. For each test vector, derive the key using BIP32 with the given seed
//! 2. Verify the derived private key matches
//! 3. Verify the public key coordinates match
//! 4. Verify the address matches
//! 5. Construct the transaction message
//! 6. Sign and verify the signature matches

pub mod transaction;
pub mod vectors;

use clap::Parser;
use std::{
    fs::File,
    io::{self, Write},
};

/// Default seed for test vector generation (32 bytes)
///
/// This is a deterministic seed used when no custom seed is provided.
/// It ensures reproducible test vectors across runs.
const DEFAULT_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Parse a hex string into a 32-byte seed
fn parse_seed(seed_str: &str) -> Result<[u8; 32], String> {
    if seed_str.len() != 64 {
        return Err(format!(
            "Seed must be exactly 64 hex characters (32 bytes), got {}",
            seed_str.len()
        ));
    }

    let bytes = hex::decode(seed_str).map_err(|e| format!("Invalid hex in seed: {}", e))?;

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Command line arguments for the test vector generator
#[derive(Parser)]
#[command(name = "generate-ledger-test-vectors")]
#[command(about = "Generate test vectors for Mina Ledger hardware wallet signing")]
#[command(long_about = r#"
Generate test vectors for validating Mina Ledger hardware wallet implementations.

The generated JSON contains:
- BIP32 key derivation test cases
- Payment and delegation transaction signatures
- Coverage for mainnet and testnet
- Multiple account indices

These test vectors can be used to validate that a Ledger implementation
produces correct signatures that will be accepted by the Mina network.
"#)]
struct Args {
    /// Output file path (use "-" or omit for stdout)
    #[arg(short, long, default_value = "-")]
    output: String,

    /// Custom seed for key derivation (64 hex characters = 32 bytes)
    ///
    /// If not provided, uses a deterministic default seed.
    #[arg(long)]
    seed: Option<String>,

    /// Verbose output (print progress to stderr)
    #[arg(short, long)]
    verbose: bool,

    /// Pretty-print JSON output (default: true)
    #[arg(long, default_value = "true")]
    pretty: bool,
}

fn main() {
    let args = Args::parse();

    // Parse or use default seed
    let seed = match &args.seed {
        Some(seed_str) => match parse_seed(seed_str) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        None => {
            if args.verbose {
                eprintln!("Using default seed: {}", hex::encode(DEFAULT_SEED));
            }
            DEFAULT_SEED
        }
    };

    if args.verbose {
        eprintln!("Generating test vectors...");
    }

    // Generate test vectors
    let vectors = vectors::generate_all_vectors(&seed);

    if args.verbose {
        eprintln!("Generated {} test vectors", vectors.test_vectors.len());
    }

    // Create output writer
    let mut writer: Box<dyn Write> = match args.output.as_str() {
        "-" => Box::new(io::stdout()),
        path => match File::create(path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("Error creating output file '{}': {}", path, e);
                std::process::exit(1);
            }
        },
    };

    // Serialize to JSON
    let result = if args.pretty {
        serde_json::to_writer_pretty(&mut writer, &vectors)
    } else {
        serde_json::to_writer(&mut writer, &vectors)
    };

    if let Err(e) = result {
        eprintln!("Error writing JSON: {}", e);
        std::process::exit(1);
    }

    // Add trailing newline for stdout
    if args.output == "-" {
        let _ = writeln!(writer);
    }

    if args.verbose {
        if args.output == "-" {
            eprintln!("Test vectors written to stdout");
        } else {
            eprintln!("Test vectors written to: {}", args.output);
        }
    }
}
