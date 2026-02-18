/// Poseidon hash prefixes used throughout the Mina protocol.
///
/// Each prefix is a 20-byte string, right-padded with `'*'` if shorter
/// than 20 characters, or truncated to 20 characters if longer.
///
/// Sources (Mina reference implementation):
/// - [hash_prefix] — re-export module
/// - [hash_prefix_states] — salted initial states
/// - [hash_prefixes] — all static prefixes
/// - [pending_coinbase] — coinbase merkle tree
/// - [zkapp_account] — events/actions empty hashes
///
/// [hash_prefix]: https://github.com/MinaProtocol/mina/blob/5bb2f568d16037a695f86c3839bad5cc5ce710da/src/lib/mina_base/hash_prefix.ml
/// [hash_prefix_states]: https://github.com/MinaProtocol/mina/blob/5bb2f568d16037a695f86c3839bad5cc5ce710da/src/lib/hash_prefix_states/hash_prefix_states.ml
/// [hash_prefixes]: https://github.com/MinaProtocol/mina/blob/5bb2f568d16037a695f86c3839bad5cc5ce710da/src/lib/hash_prefixes/hash_prefixes.ml
/// [pending_coinbase]: https://github.com/MinaProtocol/mina/blob/5bb2f568d16037a695f86c3839bad5cc5ce710da/src/lib/mina_base/pending_coinbase.ml
/// [zkapp_account]: https://github.com/MinaProtocol/mina/blob/5bb2f568d16037a695f86c3839bad5cc5ce710da/src/lib/mina_base/zkapp_account.ml
extern crate alloc;
use alloc::format;

pub const LENGTH_IN_BYTES: usize = 20;
pub const PADDING_CHAR: u8 = b'*';

/// Pad or truncate `s` to exactly [`LENGTH_IN_BYTES`], matching the
/// OCaml `Hash_prefixes.T.create` function.
#[must_use]
pub fn create(s: &str) -> [u8; LENGTH_IN_BYTES] {
    let mut buf = [PADDING_CHAR; LENGTH_IN_BYTES];
    let len = s.len().min(LENGTH_IN_BYTES);
    buf[..len].copy_from_slice(&s.as_bytes()[..len]);
    buf
}

// ---------------------------------------------------------------
// Static prefixes (from hash_prefixes.ml)
// ---------------------------------------------------------------

pub const ACCOUNT: &str = "MinaAccount*********";
pub const ACCOUNT_UPDATE_ACCOUNT_PRECONDITION: &str = "MinaAcctUpdAcctPred*";
pub const ACCOUNT_UPDATE_CONS: &str = "MinaAcctUpdateCons**";
pub const ACCOUNT_UPDATE_NODE: &str = "MinaAcctUpdateNode**";
pub const ACCOUNT_UPDATE_STACK_FRAME: &str = "MinaAcctUpdStckFrm**";
pub const ACCOUNT_UPDATE_STACK_FRAME_CONS: &str = "MinaActUpStckFrmCons";
pub const BASE_SNARK: &str = "MinaBaseSnark*******";
pub const BOWE_GABIZON_HASH: &str = "MinaTockBGHash******";
pub const CHECKPOINT_LIST: &str = "MinaCheckpoints*****";
pub const COINBASE: &str = "Coinbase************";
pub const COINBASE_STACK: &str = "CoinbaseStack*******";
pub const COINBASE_STACK_DATA: &str = "CoinbaseStackData***";
pub const COINBASE_STACK_STATE_HASH: &str = "CoinbaseStackStaHash";
pub const DERIVE_TOKEN_ID: &str = "MinaDeriveTokenId***";
pub const EPOCH_SEED: &str = "MinaEpochSeed*******";
pub const MERGE_SNARK: &str = "MinaMergeSnark******";
pub const PENDING_COINBASES: &str = "PendingCoinbases****";
pub const PROTOCOL_STATE: &str = "MinaProtoState******";
pub const PROTOCOL_STATE_BODY: &str = "MinaProtoStateBody**";
pub const RECEIPT_CHAIN_USER_COMMAND: &str = "CodaReceiptUC*******";
pub const RECEIPT_CHAIN_ZKAPP: &str = "CodaReceiptZkapp****";
pub const SIDE_LOADED_VK: &str = "MinaSideLoadedVk****";
pub const SIGNATURE_MAINNET: &str = "MinaSignatureMainnet";
pub const SIGNATURE_TESTNET: &str = "CodaSignature*******";
pub const TRANSITION_SYSTEM_SNARK: &str = "MinaTransitionSnark*";
pub const VRF_EVALUATION: &str = "MinaVrfEvaluation***";
pub const VRF_MESSAGE: &str = "MinaVrfMessage******";
pub const VRF_OUTPUT: &str = "MinaVrfOutput*******";
pub const ZKAPP_ACCOUNT: &str = "MinaZkappAccount****";
pub const ZKAPP_ACTIONS: &str = "MinaZkappSeqEvents**";
pub const ZKAPP_BODY_MAINNET: &str = "MainnetZkappBody****";
pub const ZKAPP_BODY_TESTNET: &str = "TestnetZkappBody****";
pub const ZKAPP_EVENT: &str = "MinaZkappEvent******";
pub const ZKAPP_EVENTS: &str = "MinaZkappEvents*****";
pub const ZKAPP_MEMO: &str = "MinaZkappMemo*******";
pub const ZKAPP_PAYLOAD: &str = "MinaZkappPayload****";
pub const ZKAPP_PRECONDITION: &str = "MinaZkappPred*******";
pub const ZKAPP_PRECONDITION_ACCOUNT: &str = "MinaZkappPredAcct***";
pub const ZKAPP_PRECONDITION_PROTOCOL_STATE: &str = "MinaZkappPredPS*****";
pub const ZKAPP_TEST: &str = "MinaZkappTest*******";
pub const ZKAPP_URI: &str = "MinaZkappUri********";

// ---------------------------------------------------------------
// Empty-hash salt phrases (from zkapp_account.ml)
// ---------------------------------------------------------------

/// Truncated from `"MinaZkappActionStateEmptyElt"`.
pub const ZKAPP_ACTION_STATE_EMPTY_ELT: &str = "MinaZkappActionState";
/// Truncated from `"MinaZkappActionsEmpty"`.
pub const ZKAPP_ACTIONS_EMPTY: &str = "MinaZkappActionsEmpt";
pub const ZKAPP_EVENTS_EMPTY: &str = "MinaZkappEventsEmpty";

// ---------------------------------------------------------------
// Pending coinbase tree (from pending_coinbase.ml)
// ---------------------------------------------------------------

/// Truncated from `"PendingCoinbaseMerkleTree"`.
pub const PENDING_COINBASE_MERKLE_TREE: &str = "PendingCoinbaseMerkl";

// ---------------------------------------------------------------
// Parameterized prefixes (from hash_prefixes.ml)
// ---------------------------------------------------------------

/// `merkle_tree(depth)` — produces `"MinaMklTree{depth:03}"`
/// padded to 20 bytes.
#[must_use]
pub fn merkle_tree(depth: u32) -> [u8; LENGTH_IN_BYTES] {
    create(&format!("MinaMklTree{depth:03}"))
}

/// `coinbase_merkle_tree(depth)` — produces
/// `"MinaCbMklTree{depth:03}"` padded to 20 bytes.
#[must_use]
pub fn coinbase_merkle_tree(depth: u32) -> [u8; LENGTH_IN_BYTES] {
    create(&format!("MinaCbMklTree{depth:03}"))
}

/// `zkapp_body(chain_name)` — produces
/// `"{chain_name}ZkappBody"` padded/truncated to 20 bytes.
#[must_use]
pub fn zkapp_body(chain_name: &str) -> [u8; LENGTH_IN_BYTES] {
    create(&format!("{chain_name}ZkappBody"))
}

/// `signature_other(chain_name)` — produces
/// `"{chain_name}Signature"` padded/truncated to 20 bytes.
#[must_use]
pub fn signature_other(chain_name: &str) -> [u8; LENGTH_IN_BYTES] {
    create(&format!("{chain_name}Signature"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_constants_match_create() {
        assert_eq!(
            ZKAPP_ACTIONS_EMPTY.as_bytes(),
            &create("MinaZkappActionsEmpty"),
        );
        assert_eq!(
            ZKAPP_ACTION_STATE_EMPTY_ELT.as_bytes(),
            &create("MinaZkappActionStateEmptyElt"),
        );
        assert_eq!(
            PENDING_COINBASE_MERKLE_TREE.as_bytes(),
            &create("PendingCoinbaseMerkleTree"),
        );
    }
}
