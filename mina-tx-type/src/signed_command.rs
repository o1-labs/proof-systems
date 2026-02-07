//! Signed command (payment and delegation) types.

use crate::{
    currency::{Amount, Fee, Nonce, Slot},
    primitives::Memo,
};
use mina_signer::{CompressedPubKey, Signature};

/// A payment payload: transfer tokens to a receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPayload {
    /// The recipient's public key.
    pub receiver_pk: CompressedPubKey,
    /// The amount to transfer.
    pub amount: Amount,
}

/// A stake delegation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakeDelegationPayload {
    /// Delegate stake to a new delegate.
    SetDelegate {
        /// The public key of the new delegate.
        new_delegate: CompressedPubKey,
    },
}

/// The body of a signed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedCommandBody {
    /// A token transfer.
    Payment(PaymentPayload),
    /// A stake delegation change.
    StakeDelegation(StakeDelegationPayload),
}

/// Common fields shared by all signed command payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommandCommon {
    /// Fee paid to the block producer.
    pub fee: Fee,
    /// Public key of the fee payer.
    pub fee_payer_pk: CompressedPubKey,
    /// Account nonce for replay protection.
    pub nonce: Nonce,
    /// Slot after which the transaction expires.
    pub valid_until: Slot,
    /// Optional memo (34 bytes).
    pub memo: Memo,
}

/// The full payload of a signed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommandPayload {
    /// Common fields (fee, nonce, memo, etc.).
    pub common: SignedCommandCommon,
    /// The transaction body (payment or delegation).
    pub body: SignedCommandBody,
}

/// A signed command: a user transaction authorized by a signature.
///
/// This covers payments (token transfers) and stake delegations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommand {
    /// The transaction payload.
    pub payload: SignedCommandPayload,
    /// The public key of the signer.
    pub signer: CompressedPubKey,
    /// The cryptographic signature authorizing this transaction.
    pub signature: Signature,
}
