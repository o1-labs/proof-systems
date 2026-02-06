//! Fee transfer types for distributing transaction fees.

use crate::{common::OneOrTwo, currency::Fee, primitives::TokenId};
use mina_signer::CompressedPubKey;

/// A single fee transfer to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleFeeTransfer {
    /// The recipient's public key.
    pub receiver_pk: CompressedPubKey,
    /// The fee amount.
    pub fee: Fee,
    /// The token for this fee transfer.
    pub fee_token: TokenId,
}

/// A fee transfer transaction distributing fees to one or two
/// recipients.
///
/// Fee transfers are system-generated transactions that distribute
/// transaction fees to SNARK workers and block producers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeTransfer(pub OneOrTwo<SingleFeeTransfer>);
