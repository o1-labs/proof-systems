//! Version bytes for Mina base58check encodings.
//!
//! Mirrors the OCaml definitions in [`version_bytes.ml`].
//!
//! Bytes `0x07`–`0x09` are unassigned in the Mina protocol (the OCaml
//! source skips straight from `0x06` to `0x0a`).
//!
//! [`version_bytes.ml`]: https://github.com/MinaProtocol/mina/blob/master/src/lib/base58_check/version_bytes.ml

/// Coinbase transaction.
pub const COINBASE: u8 = 0x01;
/// Secret-box encrypted bytes.
pub const SECRET_BOX_BYTESWR: u8 = 0x02;
/// Single fee transfer.
pub const FEE_TRANSFER_SINGLE: u8 = 0x03;
/// Frontier hash (Merkle tree frontier).
pub const FRONTIER_HASH: u8 = 0x04;
/// Ledger hash.
pub const LEDGER_HASH: u8 = 0x05;
/// Lite precomputed block.
pub const LITE_PRECOMPUTED: u8 = 0x06;
// 0x07–0x09 are unassigned.
/// SNARK proof.
pub const PROOF: u8 = 0x0a;
/// Random oracle base element.
pub const RANDOM_ORACLE_BASE: u8 = 0x0b;
/// Receipt chain hash.
pub const RECEIPT_CHAIN_HASH: u8 = 0x0c;
/// Epoch seed.
pub const EPOCH_SEED: u8 = 0x0d;
/// Staged ledger hash auxiliary data hash.
pub const STAGED_LEDGER_HASH_AUX_HASH: u8 = 0x0e;
/// Staged ledger hash pending coinbase auxiliary data.
pub const STAGED_LEDGER_HASH_PENDING_COINBASE_AUX: u8 = 0x0f;
/// Protocol state hash.
pub const STATE_HASH: u8 = 0x10;
/// Protocol state body hash.
pub const STATE_BODY_HASH: u8 = 0x11;
/// V1 transaction hash (legacy).
pub const V1_TRANSACTION_HASH: u8 = 0x12;
/// Signed command (V1).
pub const SIGNED_COMMAND_V1: u8 = 0x13;
/// User command memo.
pub const USER_COMMAND_MEMO: u8 = 0x14;
/// VRF truncated output.
pub const VRF_TRUNCATED_OUTPUT: u8 = 0x15;
/// Web pipe identifier.
pub const WEB_PIPE: u8 = 0x16;
/// Coinbase stack data.
pub const COINBASE_STACK_DATA: u8 = 0x17;
/// Coinbase stack hash.
pub const COINBASE_STACK_HASH: u8 = 0x18;
/// Pending coinbase hash builder.
pub const PENDING_COINBASE_HASH_BUILDER: u8 = 0x19;
/// zkApp command.
pub const ZKAPP_COMMAND: u8 = 0x1a;
/// Verification key.
pub const VERIFICATION_KEY: u8 = 0x1b;
/// Token identifier.
pub const TOKEN_ID_KEY: u8 = 0x1c;
/// Transaction hash (current version).
pub const TRANSACTION_HASH: u8 = 0x1d;

/// Ledger hash used for testing only.
pub const LEDGER_TEST_HASH: u8 = 0x30;

// Non-sequential version bytes. Existing user key infrastructure
// depends on them -- do not change.

/// Private key scalar.
pub const SECRET_KEY: u8 = 0x5a;
/// Schnorr signature.
pub const SIGNATURE: u8 = 0x9a;
/// Compressed non-zero curve point (public key / address).
pub const NON_ZERO_CURVE_POINT_COMPRESSED: u8 = 0xcb;
