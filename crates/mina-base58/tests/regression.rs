use mina_base58::{decode, encode, version};

// ================================================================
// Regression tests for every version byte.
//
// Where available, tests use real base58check strings found in the
// Mina OCaml codebase (MinaProtocol/mina). Sources include:
//   - src/app/heap_usage/values.ml
//   - src/lib/mina_block/tests/sample_precomputed_block.ml
//   - src/lib/transaction/transaction_hash.ml
//   - src/lib/crypto/key_gen/sample_keypairs.ml
//   - genesis_ledgers/devnet.json
//
// For version bytes with no known real-world base58 strings in the
// codebase (internal/legacy types), a synthetic vector is used.
// ================================================================

// --- Real values from the Mina OCaml codebase ---

#[test]
fn test_regression_ledger_hash() {
    // src/app/heap_usage/values.ml — ledger_hash field
    let b58 = "jwtL47nyjgCexDufj4YvsvG3CnQTUoFx3DWqw9agMYbABy4mGyf";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::LEDGER_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_receipt_chain_hash() {
    // src/app/heap_usage/values.ml — receipt_chain_hash field
    let b58 = "2n1AGrTWkL9TfbJA11CvoGBBtqsJ9EyF4ZTqFYEEJPjHA6ycdnau";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::RECEIPT_CHAIN_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_epoch_seed() {
    // src/app/heap_usage/values.ml — seed field
    let b58 = "2va9BGv9JrLTtrzZttiEMDYw1Zj6a6EHzXjmP9evHDTG3oEquURA";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::EPOCH_SEED);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_staged_ledger_hash_aux_hash() {
    // src/app/heap_usage/values.ml — aux_hash field
    let b58 = "VP3JQqSRC89B9jssP8oDX5otYuiK2gjqDjxnu2rLu2YmUPMnjF";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::STAGED_LEDGER_HASH_AUX_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_staged_ledger_hash_pending_coinbase_aux() {
    // src/app/heap_usage/values.ml — pending_coinbase_aux field
    let b58 = "Wb66BTQUERqbNyqudPDrKUuxeUPAUDCFDnRFcp8psdDp9J6aWj";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::STAGED_LEDGER_HASH_PENDING_COINBASE_AUX);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_state_hash() {
    // src/app/heap_usage/values.ml — previous_state_hash field
    let b58 = "3NKferWCWXycpwMdonyEMbbzViTgTkQrioeBKYMmLZFcYvC4CK9Y";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::STATE_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_state_body_hash() {
    // src/app/heap_usage/values.ml — state_body_hash field
    let b58 = "3WuibKRQv4TmqEj48a39QehVueRp8fCZ1Ta4CHfCLdVGG1y2HvDy";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::STATE_BODY_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_v1_transaction_hash() {
    // src/lib/transaction/transaction_hash.ml — V1 hash test vector
    let b58 = "CkpZirFuoLVVab6x2ry4j8Ld5gMmQdak7VHW6f5C7VJYE34WAEWqa";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::V1_TRANSACTION_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_user_command_memo() {
    // src/app/heap_usage/values.ml — memo field
    let b58 = "E4QqiVG8rCzSPqdgMPUP59hA8yMWV6m8YSYGSYBAofr6mLp16UFnM";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::USER_COMMAND_MEMO);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_coinbase_stack_data() {
    // src/app/heap_usage/values.ml — pending_coinbase data field
    let b58 = "4QNrZFBTDQCPfEZqBZsaPYx8qdaNFv1nebUyCUsQW9QUJqyuD3un";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::COINBASE_STACK_DATA);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_coinbase_stack_hash() {
    // src/app/heap_usage/values.ml — pending_coinbase init/curr field
    let b58 = "4Yyn1M4UrgyM5eRbAC1gVYkABx2mdTVDETmrAtAg5DsgnJYw9gNk";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::COINBASE_STACK_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_token_id_key() {
    // src/app/heap_usage/values.ml — token field
    let b58 = "wSHV2S4qX9jFsLjQo8r1BsMLH2ZRKsZx6EJd1sbozGPieEC4Jf";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::TOKEN_ID_KEY);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_transaction_hash() {
    // src/lib/transaction/transaction_hash.ml — current hash test vector
    let b58 = "5JuV53FPXad1QLC46z7wsou9JjjYP87qaUeryscZqLUMmLSg8j2n";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::TRANSACTION_HASH);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_secret_key() {
    // src/lib/crypto/key_gen/sample_keypairs.ml
    let b58 = "EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::SECRET_KEY);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_signature() {
    // src/app/heap_usage/values.ml — signature field
    let b58 = "7mXFbws8zFVHDngRcRgUAs9gvWcJ4ZDmXrjXozyhhNyM1KrR2Xs\
                    BzSQGDSR4ghD5Dip13iFrnweGKB5mguDmDLhk1h87etB8";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::SIGNATURE);
    assert_eq!(encode(ver, &payload), b58);
}

#[test]
fn test_regression_non_zero_curve_point_compressed() {
    // src/lib/rosetta_lib/test/test_encodings.ml — public key
    let b58 = "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy";
    let (ver, payload) = decode(b58).unwrap();
    assert_eq!(ver, version::NON_ZERO_CURVE_POINT_COMPRESSED);
    assert_eq!(encode(ver, &payload), b58);
}

// --- Synthetic vectors for version bytes without known real-world
//     base58 strings in the Mina codebase. Payload b"mina" is used
//     as a fixed canary to detect accidental encoding changes. ---

#[test]
fn test_regression_coinbase() {
    assert_eq!(encode(version::COINBASE, b"mina"), "247xFW3uwcPN");
}

#[test]
fn test_regression_secret_box_byteswr() {
    assert_eq!(encode(version::SECRET_BOX_BYTESWR, b"mina"), "2nwUT4hk16hQ");
}

#[test]
fn test_regression_fee_transfer_single() {
    assert_eq!(
        encode(version::FEE_TRANSFER_SINGLE, b"mina"),
        "3XkzedPUBCtn"
    );
}

#[test]
fn test_regression_frontier_hash() {
    assert_eq!(encode(version::FRONTIER_HASH, b"mina"), "4GaWrC3CHzXP");
}

#[test]
fn test_regression_lite_precomputed() {
    assert_eq!(encode(version::LITE_PRECOMPUTED, b"mina"), "5kDZFKKd4YWQ");
}

#[test]
fn test_regression_proof() {
    assert_eq!(encode(version::PROOF, b"mina"), "8hVe3Ztbod6w");
}

#[test]
fn test_regression_random_oracle_base() {
    assert_eq!(encode(version::RANDOM_ORACLE_BASE, b"mina"), "9SKAF8YYj7ZC");
}

#[test]
fn test_regression_signed_command_v1() {
    assert_eq!(encode(version::SIGNED_COMMAND_V1, b"mina"), "FLsKqdmhdyNm");
}

#[test]
fn test_regression_vrf_truncated_output() {
    assert_eq!(
        encode(version::VRF_TRUNCATED_OUTPUT, b"mina"),
        "GpWNEm1sMsSH"
    );
}

#[test]
fn test_regression_web_pipe() {
    assert_eq!(encode(version::WEB_PIPE, b"mina"), "HZKtSKegmEAv");
}

#[test]
fn test_regression_pending_coinbase_hash_builder() {
    // Note: the OCaml codebase incorrectly uses RECEIPT_CHAIN_HASH
    // (0x0c) for pending_coinbase Hash_builder instead of this byte.
    // No real-world string with version 0x19 exists.
    assert_eq!(
        encode(version::PENDING_COINBASE_HASH_BUILDER, b"mina"),
        "KmnT31c8jxCg"
    );
}

#[test]
fn test_regression_zkapp_command() {
    assert_eq!(encode(version::ZKAPP_COMMAND, b"mina"), "LWbyEaEn2x1h");
}

#[test]
fn test_regression_verification_key() {
    assert_eq!(encode(version::VERIFICATION_KEY, b"mina"), "MFRVS8thFxBt");
}

#[test]
fn test_regression_ledger_test_hash() {
    assert_eq!(encode(version::LEDGER_TEST_HASH, b"mina"), "ckdRcxXddHJJ");
}
