//! Precondition types for zkApp account updates.

use mina_curves::pasta::Fp;
use mina_signer::CompressedPubKey;

use crate::{
    common::{EqCheck, HashCheck, NumericCheck},
    currency::{Amount, Balance, Length, Nonce, Slot},
};

/// Epoch ledger preconditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochLedger {
    /// Hash of the epoch ledger.
    pub hash: HashCheck<Fp>,
    /// Total currency in the epoch ledger.
    pub total_currency: NumericCheck<Amount>,
}

/// Epoch data preconditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochData {
    /// Epoch ledger preconditions.
    pub ledger: EpochLedger,
    /// Epoch seed.
    pub seed: HashCheck<Fp>,
    /// Start checkpoint hash.
    pub start_checkpoint: HashCheck<Fp>,
    /// Lock checkpoint hash.
    pub lock_checkpoint: HashCheck<Fp>,
    /// Epoch length.
    pub epoch_length: NumericCheck<Length>,
}

/// Network (protocol state) preconditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPreconditions {
    /// Hash of the snarked ledger.
    pub snarked_ledger_hash: HashCheck<Fp>,
    /// Blockchain length (block height).
    pub blockchain_length: NumericCheck<Length>,
    /// Minimum window density.
    pub min_window_density: NumericCheck<Length>,
    /// Total currency in circulation.
    pub total_currency: NumericCheck<Amount>,
    /// Global slot since genesis.
    pub global_slot_since_genesis: NumericCheck<Slot>,
    /// Staking epoch data.
    pub staking_epoch_data: EpochData,
    /// Next epoch data.
    pub next_epoch_data: EpochData,
}

/// Account preconditions for a zkApp account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPrecondition {
    /// Balance range check.
    pub balance: NumericCheck<Balance>,
    /// Nonce range check.
    pub nonce: NumericCheck<Nonce>,
    /// Receipt chain hash check.
    pub receipt_chain_hash: HashCheck<Fp>,
    /// Delegate public key check.
    pub delegate: EqCheck<CompressedPubKey>,
    /// zkApp state field checks (8 fields).
    pub state: [EqCheck<Fp>; 8],
    /// Action state check.
    pub action_state: EqCheck<Fp>,
    /// Whether the account has proved state.
    pub proved_state: EqCheck<bool>,
    /// Whether the account is new.
    pub is_new: EqCheck<bool>,
}

/// All preconditions for a zkApp account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preconditions {
    /// Network (protocol state) preconditions.
    pub network: NetworkPreconditions,
    /// Account preconditions.
    pub account: AccountPrecondition,
    /// Valid-while slot range.
    pub valid_while: NumericCheck<Slot>,
}
