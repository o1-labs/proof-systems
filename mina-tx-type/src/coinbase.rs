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
//!
//! # References
//!
//! - [zkApp Signing RFC](https://mina-rust.o1labs.org/researchers/zkapp-signing)
//!
//! TODO: See issue <https://github.com/o1-labs/mina-rust/issues/1748> for
//! zkApp transaction signing documentation.

use crate::currency::{Amount, Fee, Magnitude};
use mina_signer::CompressedPubKey;

/// A fee transfer within a coinbase transaction.
///
/// When a SNARK worker contributes proofs to a block, they may receive
/// a portion of the coinbase reward as compensation. This structure
/// represents that fee transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseFeeTransfer {
    /// The public key of the fee recipient (typically a SNARK worker).
    pub receiver_pk: CompressedPubKey,
    /// The fee amount to transfer to the receiver.
    pub fee: Fee,
}

impl CoinbaseFeeTransfer {
    /// Creates a new coinbase fee transfer.
    ///
    /// # Arguments
    ///
    /// * `receiver_pk` - The compressed public key of the fee recipient
    /// * `fee` - The fee amount to transfer
    pub fn new(receiver_pk: CompressedPubKey, fee: Fee) -> Self {
        Self { receiver_pk, fee }
    }
}

/// A coinbase transaction for block rewards.
///
/// The coinbase transaction is included in each block to:
/// 1. Credit the block producer with the coinbase reward
/// 2. Optionally transfer a fee to a SNARK worker who contributed proofs
///
/// # Fields
///
/// The `amount` represents the total coinbase reward for the block.
/// If a `fee_transfer` is present, the fee is deducted from the amount
/// before crediting the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coinbase {
    /// The public key of the coinbase receiver (block producer).
    pub receiver: CompressedPubKey,
    /// The total coinbase amount for this block.
    pub amount: Amount,
    /// Optional fee transfer to a SNARK worker.
    ///
    /// If present, this fee is paid from the coinbase reward to compensate
    /// the SNARK worker for their proof work.
    pub fee_transfer: Option<CoinbaseFeeTransfer>,
}

impl Coinbase {
    /// Creates a new coinbase transaction without a fee transfer.
    ///
    /// # Arguments
    ///
    /// * `receiver` - The compressed public key of the block producer
    /// * `amount` - The coinbase reward amount
    pub fn new(receiver: CompressedPubKey, amount: Amount) -> Self {
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
    pub fn with_fee_transfer(
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

    /// Returns the net amount credited to the block producer.
    ///
    /// This is the coinbase amount minus any fee transfer.
    /// Returns `None` if the fee exceeds the amount (which should not
    /// happen in valid transactions).
    pub fn net_amount(&self) -> Option<Amount> {
        match &self.fee_transfer {
            Some(ft) => {
                let fee_as_amount = Amount::new(ft.fee.inner());
                self.amount.checked_sub(&fee_as_amount)
            }
            None => Some(self.amount),
        }
    }

    /// Returns `true` if this coinbase has a fee transfer.
    pub fn has_fee_transfer(&self) -> bool {
        self.fee_transfer.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_fee_transfer_new() {
        let pk = CompressedPubKey::empty();
        let fee = Fee::new(1_000_000);
        let ft = CoinbaseFeeTransfer::new(pk.clone(), fee);

        assert_eq!(ft.receiver_pk, pk);
        assert_eq!(ft.fee, fee);
    }

    #[test]
    fn test_coinbase_new() {
        let pk = CompressedPubKey::empty();
        let amount = Amount::new(720_000_000_000); // 720 MINA

        let cb = Coinbase::new(pk.clone(), amount);

        assert_eq!(cb.receiver, pk);
        assert_eq!(cb.amount, amount);
        assert!(cb.fee_transfer.is_none());
        assert!(!cb.has_fee_transfer());
        assert_eq!(cb.net_amount(), Some(amount));
    }

    #[test]
    fn test_coinbase_with_fee_transfer() {
        let producer_pk = CompressedPubKey::empty();
        let snark_pk = CompressedPubKey::empty();
        let amount = Amount::new(720_000_000_000); // 720 MINA
        let fee = Fee::new(1_000_000_000); // 1 MINA

        let ft = CoinbaseFeeTransfer::new(snark_pk.clone(), fee);
        let cb = Coinbase::with_fee_transfer(producer_pk.clone(), amount, ft);

        assert_eq!(cb.receiver, producer_pk);
        assert_eq!(cb.amount, amount);
        assert!(cb.has_fee_transfer());

        let net = cb.net_amount().unwrap();
        assert_eq!(net, Amount::new(719_000_000_000)); // 720 - 1 = 719 MINA
    }

    #[test]
    fn test_coinbase_net_amount_underflow() {
        let pk = CompressedPubKey::empty();
        let amount = Amount::new(1_000_000); // 0.001 MINA
        let fee = Fee::new(1_000_000_000); // 1 MINA (more than amount)

        let ft = CoinbaseFeeTransfer::new(pk.clone(), fee);
        let cb = Coinbase::with_fee_transfer(pk, amount, ft);

        // Fee exceeds amount, should return None
        assert!(cb.net_amount().is_none());
    }
}
