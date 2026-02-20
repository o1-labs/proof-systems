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
//! - [`Coinbase`]: Block reward transactions
//! - [`CoinbaseFeeTransfer`]: Fee transfers within coinbase transactions
//! - [`SignedCommand`]: Signed user commands (payments and delegations)
//! - [`ZkAppCommand`]: zkApp commands with account updates
//! - [`FeeTransfer`]: System fee transfer transactions
//! - [`Transaction`]: Top-level transaction enum
//! - [`UserCommand`]: User-initiated command enum
//!
//! # Currency Types
//!
//! - [`Amount`]: Currency amounts in nanomina
//! - [`Fee`]: Transaction fees in nanomina
//! - [`Balance`]: Account balances in nanomina
//! - [`Nonce`]: Account nonces
//! - [`Slot`]: Global slot numbers
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

extern crate alloc;

pub mod coinbase;
pub mod common;
pub mod currency;
pub mod fee_transfer;
pub mod permissions;
pub mod preconditions;
pub mod primitives;
pub mod signed_command;
pub mod transaction;
pub mod zkapp_command;

// Re-export main types at crate root for convenience
pub use coinbase::{Coinbase, CoinbaseFeeTransfer};
pub use common::{ClosedInterval, OneOrTwo, OrIgnore, SetOrKeep};
pub use currency::{
    Amount, Balance, Fee, Length, Magnitude, Nonce, Sign, Signed, Slot, SlotSpan, TxnVersion,
};
pub use fee_transfer::{FeeTransfer, SingleFeeTransfer};
pub use permissions::{AuthRequired, Permissions, SetVerificationKey};
pub use preconditions::Preconditions;
pub use primitives::{AccountId, Memo, TokenId, TokenSymbol, VotingFor, ZkAppUri};
pub use signed_command::{
    PaymentPayload, SignedCommand, SignedCommandBody, SignedCommandCommon, SignedCommandPayload,
    StakeDelegationPayload,
};
pub use transaction::{Transaction, UserCommand};
pub use zkapp_command::{
    AccountUpdate, AccountUpdateBody, AccountUpdateTree, Actions, AuthorizationKind, Control,
    Event, Events, FeePayer, FeePayerBody, MayUseToken, ProofVerified, Timing, Update,
    VerificationKey, ZkAppCommand,
};
