//! Coinbase transaction types for Mina Protocol.
//!
//! This module defines the coinbase transaction structures used for
//! block rewards and fee transfers in the Mina Protocol.
//!
//! # Overview
//!
//! In Mina, each block can include a coinbase transaction that:
//! - Rewards the block producer with newly minted tokens
//! - Optionally transfers a portion of the reward as a fee to a SNARK worker

use crate::currency::{Amount, Fee, Magnitude};
use mina_signer::CompressedPubKey;

/// A fee transfer within a coinbase transaction.
///
/// When a SNARK worker contributes proofs to a block, they may receive
/// a portion of the coinbase reward as compensation. This structure
/// represents that fee transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseFeeTransfer {
    receiver_pk: CompressedPubKey,
    fee: Fee,
}

impl CoinbaseFeeTransfer {
    /// Creates a new coinbase fee transfer.
    ///
    /// # Arguments
    ///
    /// * `receiver_pk` - The compressed public key of the fee recipient
    /// * `fee` - The fee amount to transfer
    #[must_use]
    pub const fn new(receiver_pk: CompressedPubKey, fee: Fee) -> Self {
        Self { receiver_pk, fee }
    }

    /// Returns the public key of the fee recipient.
    #[must_use]
    pub const fn receiver_pk(&self) -> &CompressedPubKey {
        &self.receiver_pk
    }

    /// Returns the fee amount.
    #[must_use]
    pub const fn fee(&self) -> Fee {
        self.fee
    }
}

/// A coinbase transaction for block rewards.
///
/// The coinbase transaction is included in each block to:
/// 1. Credit the block producer with the coinbase reward
/// 2. Optionally transfer a fee to a SNARK worker who contributed proofs
///
/// The `amount` represents the total coinbase reward for the block.
/// If a `fee_transfer` is present, the fee is deducted from the amount
/// before crediting the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coinbase {
    receiver: CompressedPubKey,
    amount: Amount,
    fee_transfer: Option<CoinbaseFeeTransfer>,
}

impl Coinbase {
    /// Creates a new coinbase transaction without a fee transfer.
    ///
    /// # Arguments
    ///
    /// * `receiver` - The compressed public key of the block producer
    /// * `amount` - The coinbase reward amount
    #[must_use]
    pub const fn new(receiver: CompressedPubKey, amount: Amount) -> Self {
        Self {
            receiver,
            amount,
            fee_transfer: None,
        }
    }

    /// Creates a new coinbase transaction with a fee transfer.
    ///
    /// # Arguments
    ///
    /// * `receiver` - The compressed public key of the block producer
    /// * `amount` - The coinbase reward amount
    /// * `fee_transfer` - The fee transfer to a SNARK worker
    #[must_use]
    pub const fn with_fee_transfer(
        receiver: CompressedPubKey,
        amount: Amount,
        fee_transfer: CoinbaseFeeTransfer,
    ) -> Self {
        Self {
            receiver,
            amount,
            fee_transfer: Some(fee_transfer),
        }
    }

    /// Returns the coinbase receiver (block producer).
    #[must_use]
    pub const fn receiver(&self) -> &CompressedPubKey {
        &self.receiver
    }

    /// Returns the total coinbase amount.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// Returns the optional fee transfer.
    #[must_use]
    pub const fn fee_transfer(&self) -> Option<&CoinbaseFeeTransfer> {
        self.fee_transfer.as_ref()
    }

    /// Returns `true` if this coinbase has a fee transfer.
    #[must_use]
    pub const fn has_fee_transfer(&self) -> bool {
        self.fee_transfer.is_some()
    }

    /// Returns the net amount credited to the block producer.
    ///
    /// This is the coinbase amount minus any fee transfer.
    /// Returns `None` if the fee exceeds the amount (which should not
    /// happen in valid transactions).
    #[must_use]
    pub fn net_amount(&self) -> Option<Amount> {
        self.fee_transfer.as_ref().map_or(Some(self.amount), |ft| {
            let fee_as_amount: Amount = ft.fee().into();
            self.amount.checked_sub(fee_as_amount)
        })
    }
}
