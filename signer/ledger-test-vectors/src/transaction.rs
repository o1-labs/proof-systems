//! Transaction types for Mina Ledger signing
//!
//! Defines the transaction structure used by the Ledger hardware wallet
//! for payment and delegation transactions.
//!
//! # Future Work
//!
//! When <https://github.com/o1-labs/mina-rust/issues/1665> is implemented,
//! we should use the transaction types from there instead of defining them here.

use mina_hasher::{Hashable, ROInput};
use mina_signer::{CompressedPubKey, NetworkId, PubKey};
use serde::{Deserialize, Serialize};

/// Memo field size in bytes
pub const MEMO_BYTES: usize = 34;

/// Number of bits in the transaction tag
pub const TAG_BITS: usize = 3;

/// Tag for payment transactions [0, 0, 0]
pub const PAYMENT_TX_TAG: [bool; TAG_BITS] = [false, false, false];

/// Tag for delegation transactions [0, 0, 1]
pub const DELEGATION_TX_TAG: [bool; TAG_BITS] = [false, false, true];

/// Mina transaction for Ledger signing
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction fee in nanomina
    pub fee: u64,
    /// Fee token ID (always 1 for MINA)
    pub fee_token: u64,
    /// Fee payer public key (compressed)
    pub fee_payer_pk: CompressedPubKey,
    /// Account nonce
    pub nonce: u32,
    /// Valid until global slot (u32::MAX for no expiry)
    pub valid_until: u32,
    /// Memo field (34 bytes)
    pub memo: [u8; MEMO_BYTES],
    /// Transaction type tag
    pub tag: [bool; TAG_BITS],
    /// Source public key (compressed)
    pub source_pk: CompressedPubKey,
    /// Receiver public key (compressed)
    pub receiver_pk: CompressedPubKey,
    /// Token ID (always 1 for MINA)
    pub token_id: u64,
    /// Amount in nanomina (0 for delegation)
    pub amount: u64,
    /// Token locked flag
    pub token_locked: bool,
}

impl Hashable for Transaction {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new()
            .append_field(self.fee_payer_pk.x)
            .append_field(self.source_pk.x)
            .append_field(self.receiver_pk.x)
            .append_u64(self.fee)
            .append_u64(self.fee_token)
            .append_bool(self.fee_payer_pk.is_odd)
            .append_u32(self.nonce)
            .append_u32(self.valid_until)
            .append_bytes(&self.memo);

        for tag_bit in self.tag {
            roi = roi.append_bool(tag_bit);
        }

        roi.append_bool(self.source_pk.is_odd)
            .append_bool(self.receiver_pk.is_odd)
            .append_u64(self.token_id)
            .append_u64(self.amount)
            .append_bool(self.token_locked)
    }

    fn domain_string(network_id: NetworkId) -> Option<String> {
        match network_id {
            NetworkId::MAINNET => "MinaSignatureMainnet",
            NetworkId::TESTNET => "CodaSignature",
        }
        .to_string()
        .into()
    }
}

impl Transaction {
    /// Create a new payment transaction
    pub fn new_payment(from: PubKey, to: PubKey, amount: u64, fee: u64, nonce: u32) -> Self {
        Transaction {
            fee,
            fee_token: 1,
            fee_payer_pk: from.into_compressed(),
            nonce,
            valid_until: u32::MAX,
            memo: core::array::from_fn(|i| (i == 0) as u8),
            tag: PAYMENT_TX_TAG,
            source_pk: from.into_compressed(),
            receiver_pk: to.into_compressed(),
            token_id: 1,
            amount,
            token_locked: false,
        }
    }

    /// Create a new delegation transaction
    pub fn new_delegation(from: PubKey, to: PubKey, fee: u64, nonce: u32) -> Self {
        Transaction {
            fee,
            fee_token: 1,
            fee_payer_pk: from.into_compressed(),
            nonce,
            valid_until: u32::MAX,
            memo: core::array::from_fn(|i| (i == 0) as u8),
            tag: DELEGATION_TX_TAG,
            source_pk: from.into_compressed(),
            receiver_pk: to.into_compressed(),
            token_id: 1,
            amount: 0,
            token_locked: false,
        }
    }

    /// Set the valid_until field
    pub fn set_valid_until(mut self, global_slot: u32) -> Self {
        self.valid_until = global_slot;
        self
    }

    /// Set the memo field from a string
    pub fn set_memo_str(mut self, memo: &str) -> Self {
        self.memo[0] = 0x01;
        self.memo[1] = core::cmp::min(memo.len(), MEMO_BYTES - 2) as u8;
        let memo = format!("{memo:\0<32}");
        self.memo[2..]
            .copy_from_slice(&memo.as_bytes()[..core::cmp::min(memo.len(), MEMO_BYTES - 2)]);
        self
    }
}

/// Transaction type for JSON serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransactionJson {
    /// Payment transaction
    #[serde(rename = "payment")]
    Payment {
        /// Receiver address (B62...)
        to: String,
        /// Amount in nanomina
        amount: String,
        /// Fee in nanomina
        fee: String,
        /// Account nonce
        nonce: u32,
        /// Valid until slot (null for no expiry)
        valid_until: Option<u32>,
        /// Memo string
        memo: String,
    },
    /// Delegation transaction
    #[serde(rename = "delegation")]
    Delegation {
        /// Delegate to address (B62...)
        to: String,
        /// Fee in nanomina
        fee: String,
        /// Account nonce
        nonce: u32,
        /// Valid until slot (null for no expiry)
        valid_until: Option<u32>,
        /// Memo string
        memo: String,
    },
}

impl TransactionJson {
    /// Create a payment transaction JSON
    pub fn payment(
        to: &str,
        amount: u64,
        fee: u64,
        nonce: u32,
        valid_until: Option<u32>,
        memo: &str,
    ) -> Self {
        TransactionJson::Payment {
            to: to.to_string(),
            amount: amount.to_string(),
            fee: fee.to_string(),
            nonce,
            valid_until,
            memo: memo.to_string(),
        }
    }

    /// Create a delegation transaction JSON
    pub fn delegation(
        to: &str,
        fee: u64,
        nonce: u32,
        valid_until: Option<u32>,
        memo: &str,
    ) -> Self {
        TransactionJson::Delegation {
            to: to.to_string(),
            fee: fee.to_string(),
            nonce,
            valid_until,
            memo: memo.to_string(),
        }
    }
}
