//! Version bytes for Mina base58check encodings.
//!
//! Mirrors the OCaml definitions in [`version_bytes.ml`].
//!
//! [`version_bytes.ml`]: https://github.com/MinaProtocol/mina/blob/master/src/lib/base58_check/version_bytes.ml

pub const COINBASE: u8 = 0x01;
pub const SECRET_BOX_BYTESWR: u8 = 0x02;
pub const FEE_TRANSFER_SINGLE: u8 = 0x03;
pub const FRONTIER_HASH: u8 = 0x04;
pub const LEDGER_HASH: u8 = 0x05;
pub const LITE_PRECOMPUTED: u8 = 0x06;
pub const PROOF: u8 = 0x0a;
pub const RANDOM_ORACLE_BASE: u8 = 0x0b;
pub const RECEIPT_CHAIN_HASH: u8 = 0x0c;
pub const EPOCH_SEED: u8 = 0x0d;
pub const STAGED_LEDGER_HASH_AUX_HASH: u8 = 0x0e;
pub const STAGED_LEDGER_HASH_PENDING_COINBASE_AUX: u8 = 0x0f;
pub const STATE_HASH: u8 = 0x10;
pub const STATE_BODY_HASH: u8 = 0x11;
pub const V1_TRANSACTION_HASH: u8 = 0x12;
pub const SIGNED_COMMAND_V1: u8 = 0x13;
pub const USER_COMMAND_MEMO: u8 = 0x14;
pub const VRF_TRUNCATED_OUTPUT: u8 = 0x15;
pub const WEB_PIPE: u8 = 0x16;
pub const COINBASE_STACK_DATA: u8 = 0x17;
pub const COINBASE_STACK_HASH: u8 = 0x18;
pub const PENDING_COINBASE_HASH_BUILDER: u8 = 0x19;
pub const ZKAPP_COMMAND: u8 = 0x1a;
pub const VERIFICATION_KEY: u8 = 0x1b;
pub const TOKEN_ID_KEY: u8 = 0x1c;
pub const TRANSACTION_HASH: u8 = 0x1d;

/// Used for testing only.
pub const LEDGER_TEST_HASH: u8 = 0x30;

// Non-sequential version bytes. Existing user key infrastructure
// depends on them -- do not change.
pub const SECRET_KEY: u8 = 0x5a;
pub const SIGNATURE: u8 = 0x9a;
pub const NON_ZERO_CURVE_POINT_COMPRESSED: u8 = 0xcb;
