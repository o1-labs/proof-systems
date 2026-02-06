//! Mina Protocol transaction types.
//!
//! This crate provides `no_std` compatible transaction type definitions for
//! the Mina Protocol. It is designed for use by external projects that need
//! access to Mina transaction types without requiring the full ledger crate's
//! dependencies.
//!
//! # Features
//!
//! - **`no_std` compatible**: Works in embedded and constrained environments
//!   such as hardware wallets and WASM runtimes.
//! - **Standalone**: Minimal dependencies, focused purely on type definitions.
//! - **Documented**: All types and fields include rustdoc documentation.
//!
//! # Transaction Types
//!
//! Currently supported transaction types:
//!
//! - [`Coinbase`]: Block reward transactions
//! - [`CoinbaseFeeTransfer`]: Fee transfers within coinbase transactions
//!
//! # Currency Types
//!
//! - [`Amount`]: Currency amounts in nanomina
//! - [`Fee`]: Transaction fees in nanomina
//! - [`Signed`]: Signed quantities with separate magnitude and sign
//! - [`Sign`]: Sign indicator (positive or negative)
//!
//! # Example
//!
//! ```
//! use mina_tx_type::{Amount, Fee, Coinbase, CoinbaseFeeTransfer};
//! use mina_signer::CompressedPubKey;
//!
//! // Create a coinbase transaction
//! let receiver = CompressedPubKey::empty();
//! let amount = Amount::new(720_000_000_000); // 720 MINA
//!
//! let coinbase = Coinbase::new(receiver, amount);
//! assert!(!coinbase.has_fee_transfer());
//! ```

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod coinbase;
pub mod currency;

// Re-export main types at crate root for convenience
pub use coinbase::{Coinbase, CoinbaseFeeTransfer};
pub use currency::{Amount, Fee, Magnitude, Sign, Signed};
