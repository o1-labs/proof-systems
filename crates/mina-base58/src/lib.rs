#![no_std]

extern crate alloc;

pub mod version;

use alloc::{string::String, vec, vec::Vec};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("invalid base58 character")]
    InvalidBase58,
    #[error("decoded data too short")]
    TooShort,
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid version byte: expected {expected:#04x}, found {found:#04x}")]
    InvalidVersion { expected: u8, found: u8 },
}

/// Double-SHA256 checksum of `data`.
pub fn checksum(data: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(&Sha256::digest(data)[..]);
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

/// Encode `payload` with a leading `version` byte in base58check.
///
/// Prepends the version byte, computes a 4-byte double-SHA256 checksum
/// over `[version || payload]`, appends it, and base58-encodes.
pub fn encode(version: u8, payload: &[u8]) -> String {
    let mut raw = vec![version];
    raw.extend_from_slice(payload);
    let cs = checksum(&raw);
    raw.extend_from_slice(&cs);
    bs58::encode(raw).into_string()
}

/// Decode a base58check string, returning `(version, payload)`.
pub fn decode(b58: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|_| DecodeError::InvalidBase58)?;
    if bytes.len() < 5 {
        return Err(DecodeError::TooShort);
    }
    let (raw, cs) = bytes.split_at(bytes.len() - 4);
    if cs != checksum(raw) {
        return Err(DecodeError::InvalidChecksum);
    }
    let version = raw[0];
    let payload = raw[1..].to_vec();
    Ok((version, payload))
}

/// Decode a base58check string and verify the version byte.
pub fn decode_version(b58: &str, expected: u8) -> Result<Vec<u8>, DecodeError> {
    let (version, payload) = decode(b58)?;
    if version != expected {
        return Err(DecodeError::InvalidVersion {
            expected,
            found: version,
        });
    }
    Ok(payload)
}

/// Encode raw bytes (which already contain any version/structure bytes)
/// with an appended 4-byte double-SHA256 checksum.
pub fn encode_raw(raw: &[u8]) -> String {
    let cs = checksum(raw);
    let mut buf = Vec::with_capacity(raw.len() + 4);
    buf.extend_from_slice(raw);
    buf.extend_from_slice(&cs);
    bs58::encode(buf).into_string()
}

/// Decode a base58check string, verify the checksum, and return the raw
/// bytes (without the trailing checksum but including any version bytes).
pub fn decode_raw(b58: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|_| DecodeError::InvalidBase58)?;
    if bytes.len() < 5 {
        return Err(DecodeError::TooShort);
    }
    let (raw, cs) = bytes.split_at(bytes.len() - 4);
    if cs != checksum(raw) {
        return Err(DecodeError::InvalidChecksum);
    }
    Ok(raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // ================================================================
    // OCaml test vectors (from mina/src/lib/base58_check/tests/)
    //
    // The OCaml tests use version byte 0x53. These vectors verify
    // that our Rust implementation matches the OCaml base58check
    // algorithm exactly.
    // ================================================================

    const OCAML_TEST_VERSION: u8 = 0x53;

    #[test]
    fn test_ocaml_vector_empty_payload() {
        let encoded = encode(OCAML_TEST_VERSION, b"");
        assert_eq!(encoded, "AR3b7Dr");
    }

    #[test]
    fn test_ocaml_vector_payload_vectors() {
        let encoded = encode(OCAML_TEST_VERSION, b"vectors");
        assert_eq!(encoded, "2aML9fKacueS1p5W3");
    }

    #[test]
    fn test_ocaml_vector_payload_test() {
        let encoded = encode(OCAML_TEST_VERSION, b"test");
        assert_eq!(encoded, "24cUQZMy5c7Mj");
    }

    #[test]
    fn test_ocaml_roundtrip_empty() {
        let encoded = encode(OCAML_TEST_VERSION, b"");
        let payload = decode_version(&encoded, OCAML_TEST_VERSION).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_ocaml_roundtrip_nonempty() {
        let input = b"Somewhere, over the rainbow, way up high";
        let encoded = encode(OCAML_TEST_VERSION, input);
        let payload = decode_version(&encoded, OCAML_TEST_VERSION).unwrap();
        assert_eq!(payload, input);
    }

    #[test]
    fn test_ocaml_roundtrip_longer() {
        let input = b"Someday, I wish upon a star, wake up where \
            the clouds are far behind me, where trouble melts \
            like lemon drops, High above the chimney top, \
            that's where you'll find me";
        let encoded = encode(OCAML_TEST_VERSION, input);
        let payload = decode_version(&encoded, OCAML_TEST_VERSION).unwrap();
        assert_eq!(payload, input);
    }

    #[test]
    fn test_ocaml_invalid_checksum() {
        let encoded = encode(OCAML_TEST_VERSION, b"Bluer than velvet were her eyes");
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == '1' { '2' } else { '1' };
        let corrupted: String = chars.into_iter().collect();
        assert_eq!(
            decode(&corrupted).unwrap_err(),
            DecodeError::InvalidChecksum
        );
    }

    #[test]
    fn test_ocaml_invalid_length() {
        // "abcd" in base58 decodes to too few bytes
        let err = decode("abcd").unwrap_err();
        assert!(err == DecodeError::TooShort || err == DecodeError::InvalidChecksum);
    }

    // ================================================================
    // State hash vectors (version 0x10) — from mina-rust
    // ================================================================

    #[test]
    fn test_state_hash_encode_1() {
        let payload = hex::decode(
            "01fc630629c6a1a237a3dc1d95fd54fbf9cca062486e\
             9f57852ebc64e4042ceb3d",
        )
        .unwrap();
        let encoded = encode(version::STATE_HASH, &payload);
        assert_eq!(
            encoded,
            "3NLx3eBDTvYmP27bUmYANzmhjL5rGe36nGW6N5XhGcuStF6Zv7ZD"
        );
    }

    #[test]
    fn test_state_hash_encode_2() {
        let payload = hex::decode(
            "019b4f7c30bcf6c883c388097db490bfeeae5a1d36eb\
             4b593af65e3511db4fc432",
        )
        .unwrap();
        let encoded = encode(version::STATE_HASH, &payload);
        assert_eq!(
            encoded,
            "3NLDHxUsL6Ehujf6x2AT6CXrpRjeY1rw9e93QJfJUAD3P6HVVtcA"
        );
    }

    #[test]
    fn test_state_hash_encode_3() {
        let payload = hex::decode(
            "018d67aadd018581a812623915b13d5c3a6da7dfe8a1\
             95172d9bbd206810bc2329",
        )
        .unwrap();
        let encoded = encode(version::STATE_HASH, &payload);
        assert_eq!(
            encoded,
            "3NL7AkynW6hbDrhHTAht1GLG563Fo9fdcEQk1zEyy5XedC6aZTeB"
        );
    }

    #[test]
    fn test_state_hash_roundtrip() {
        let hashes = [
            "3NLx3eBDTvYmP27bUmYANzmhjL5rGe36nGW6N5XhGcuStF6Zv7ZD",
            "3NLDHxUsL6Ehujf6x2AT6CXrpRjeY1rw9e93QJfJUAD3P6HVVtcA",
            "3NL7AkynW6hbDrhHTAht1GLG563Fo9fdcEQk1zEyy5XedC6aZTeB",
        ];
        for h in hashes {
            let (ver, payload) = decode(h).unwrap();
            assert_eq!(ver, version::STATE_HASH);
            assert_eq!(encode(ver, &payload), h);
        }
    }

    // ================================================================
    // Ledger hash vectors (version 0x05) — from mina-rust
    // ================================================================

    #[test]
    fn test_ledger_hash_roundtrip() {
        let expected = "jwrPvAMUNo3EKT2puUk5Fxz6B7apRAoKNTGpAA49t3TRSfzvdrL";
        let (ver, payload) = decode(expected).unwrap();
        assert_eq!(ver, version::LEDGER_HASH);
        assert_eq!(encode(ver, &payload), expected);
    }

    // ================================================================
    // Address / public key vectors (version 0xcb) — from mina-rust
    // ================================================================

    #[test]
    fn test_address_encode() {
        let payload = hex::decode(
            "01013c2b5b48c22dc8b8c9d2c9d76a2ceaaf02beabb3\
             64301726c3f8e989653af51300",
        )
        .unwrap();
        let encoded = encode(version::NON_ZERO_CURVE_POINT_COMPRESSED, &payload);
        assert_eq!(
            encoded,
            "B62qkUHaJUHERZuCHQhXCQ8xsGBqyYSgjQsKnKN5HhSJecakuJ4pYyk"
        );
    }

    #[test]
    fn test_address_roundtrip() {
        let expected = "B62qkUHaJUHERZuCHQhXCQ8xsGBqyYSgjQsKnKN5HhSJecakuJ4pYyk";
        let (ver, payload) = decode(expected).unwrap();
        assert_eq!(ver, version::NON_ZERO_CURVE_POINT_COMPRESSED);
        assert_eq!(encode(ver, &payload), expected);
    }

    // ================================================================
    // Address roundtrip tests — from mina-signer
    // ================================================================

    #[test]
    fn test_address_roundtrip_signer_vectors() {
        let addresses = [
            "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
            "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
            "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4",
            "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi",
            "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
            "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M",
        ];
        for addr in addresses {
            let (ver, payload) = decode(addr).unwrap();
            assert_eq!(ver, version::NON_ZERO_CURVE_POINT_COMPRESSED);
            assert_eq!(encode(ver, &payload), addr);
        }
    }

    // ================================================================
    // Secret key roundtrip — from mina-signer
    // ================================================================

    #[test]
    fn test_secret_key_roundtrip_raw() {
        let b58 = "EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodY";
        let raw = decode_raw(b58).unwrap();
        assert_eq!(raw[0], version::SECRET_KEY);
        assert_eq!(encode_raw(&raw), b58);
    }

    #[test]
    fn test_secret_key_roundtrip_versioned() {
        let b58 = "EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodY";
        let payload = decode_version(b58, version::SECRET_KEY).unwrap();
        assert_eq!(encode(version::SECRET_KEY, &payload), b58);
    }

    // ================================================================
    // Checksum verification
    // ================================================================

    #[test]
    fn test_checksum_is_deterministic() {
        let data = b"hello world";
        assert_eq!(checksum(data), checksum(data));
    }

    #[test]
    fn test_checksum_differs_for_different_data() {
        assert_ne!(checksum(b"aaa"), checksum(b"bbb"));
    }

    #[test]
    fn test_checksum_is_four_bytes() {
        let cs = checksum(b"any data");
        assert_eq!(cs.len(), 4);
    }

    // ================================================================
    // Encode / decode property tests
    // ================================================================

    #[test]
    fn test_encode_decode_roundtrip_all_version_bytes() {
        let payload = b"test payload";
        let versions: &[u8] = &[
            version::COINBASE,
            version::SECRET_BOX_BYTESWR,
            version::FEE_TRANSFER_SINGLE,
            version::FRONTIER_HASH,
            version::LEDGER_HASH,
            version::LITE_PRECOMPUTED,
            version::PROOF,
            version::RANDOM_ORACLE_BASE,
            version::RECEIPT_CHAIN_HASH,
            version::EPOCH_SEED,
            version::STAGED_LEDGER_HASH_AUX_HASH,
            version::STAGED_LEDGER_HASH_PENDING_COINBASE_AUX,
            version::STATE_HASH,
            version::STATE_BODY_HASH,
            version::V1_TRANSACTION_HASH,
            version::SIGNED_COMMAND_V1,
            version::USER_COMMAND_MEMO,
            version::VRF_TRUNCATED_OUTPUT,
            version::WEB_PIPE,
            version::COINBASE_STACK_DATA,
            version::COINBASE_STACK_HASH,
            version::PENDING_COINBASE_HASH_BUILDER,
            version::ZKAPP_COMMAND,
            version::VERIFICATION_KEY,
            version::TOKEN_ID_KEY,
            version::TRANSACTION_HASH,
            version::LEDGER_TEST_HASH,
            version::SECRET_KEY,
            version::SIGNATURE,
            version::NON_ZERO_CURVE_POINT_COMPRESSED,
        ];
        for &ver in versions {
            let encoded = encode(ver, payload);
            let (decoded_ver, decoded_payload) = decode(&encoded).unwrap();
            assert_eq!(decoded_ver, ver);
            assert_eq!(decoded_payload, payload);
        }
    }

    #[test]
    fn test_encode_raw_decode_raw_roundtrip() {
        let raw = b"\x10\x01\x02\x03some data";
        let encoded = encode_raw(raw);
        let decoded = decode_raw(&encoded).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_encode_decode_empty_payload() {
        let encoded = encode(0xff, &[]);
        let (ver, payload) = decode(&encoded).unwrap();
        assert_eq!(ver, 0xff);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_encode_decode_single_byte_payload() {
        let encoded = encode(0x01, &[0x42]);
        let (ver, payload) = decode(&encoded).unwrap();
        assert_eq!(ver, 0x01);
        assert_eq!(payload, [0x42]);
    }

    #[test]
    fn test_encode_decode_large_payload() {
        let payload = vec![0xab; 256];
        let encoded = encode(0x10, &payload);
        let (ver, decoded) = decode(&encoded).unwrap();
        assert_eq!(ver, 0x10);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_encode_decode_all_zeros_payload() {
        let payload = vec![0x00; 32];
        let encoded = encode(version::STATE_HASH, &payload);
        let (ver, decoded) = decode(&encoded).unwrap();
        assert_eq!(ver, version::STATE_HASH);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_encode_decode_all_ones_payload() {
        let payload = vec![0xff; 32];
        let encoded = encode(version::STATE_HASH, &payload);
        let (ver, decoded) = decode(&encoded).unwrap();
        assert_eq!(ver, version::STATE_HASH);
        assert_eq!(decoded, payload);
    }

    // ================================================================
    // decode_version tests
    // ================================================================

    #[test]
    fn test_decode_version_correct() {
        let encoded = encode(version::STATE_HASH, b"data");
        let payload = decode_version(&encoded, version::STATE_HASH).unwrap();
        assert_eq!(payload, b"data");
    }

    #[test]
    fn test_decode_version_wrong() {
        let encoded = encode(version::STATE_HASH, b"data");
        let err = decode_version(&encoded, version::LEDGER_HASH).unwrap_err();
        assert_eq!(
            err,
            DecodeError::InvalidVersion {
                expected: version::LEDGER_HASH,
                found: version::STATE_HASH,
            }
        );
    }

    // ================================================================
    // Error cases
    // ================================================================

    #[test]
    fn test_decode_invalid_base58_chars() {
        // 0, O, I, l are not in the base58 alphabet
        assert_eq!(decode("0OIl").unwrap_err(), DecodeError::InvalidBase58);
    }

    #[test]
    fn test_decode_too_short() {
        // "1" encodes to a single zero byte
        assert_eq!(decode("1").unwrap_err(), DecodeError::TooShort);
    }

    #[test]
    fn test_decode_too_short_two_bytes() {
        assert_eq!(decode("11").unwrap_err(), DecodeError::TooShort);
    }

    #[test]
    fn test_decode_too_short_three_bytes() {
        assert_eq!(decode("111").unwrap_err(), DecodeError::TooShort);
    }

    #[test]
    fn test_decode_too_short_four_bytes() {
        assert_eq!(decode("1111").unwrap_err(), DecodeError::TooShort);
    }

    #[test]
    fn test_decode_corrupted_checksum_state_hash() {
        let valid = "3NLx3eBDTvYmP27bUmYANzmhjL5rGe36nGW6N5XhGcuStF6Zv7ZD";
        let mut chars: Vec<char> = valid.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert_eq!(
            decode(&corrupted).unwrap_err(),
            DecodeError::InvalidChecksum
        );
    }

    #[test]
    fn test_decode_corrupted_checksum_address() {
        let valid = "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV";
        let mut chars: Vec<char> = valid.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == '1' { '2' } else { '1' };
        let corrupted: String = chars.into_iter().collect();
        assert_eq!(
            decode(&corrupted).unwrap_err(),
            DecodeError::InvalidChecksum
        );
    }

    #[test]
    fn test_decode_empty_input() {
        let err = decode("").unwrap_err();
        assert!(err == DecodeError::InvalidBase58 || err == DecodeError::TooShort);
    }

    #[test]
    fn test_decode_raw_invalid_base58() {
        assert_eq!(decode_raw("0OIl").unwrap_err(), DecodeError::InvalidBase58);
    }

    #[test]
    fn test_decode_raw_too_short() {
        assert_eq!(decode_raw("1").unwrap_err(), DecodeError::TooShort);
    }

    #[test]
    fn test_decode_raw_corrupted_checksum() {
        let valid = encode_raw(b"\x10test");
        let mut chars: Vec<char> = valid.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == '1' { '2' } else { '1' };
        let corrupted: String = chars.into_iter().collect();
        assert_eq!(
            decode_raw(&corrupted).unwrap_err(),
            DecodeError::InvalidChecksum
        );
    }

    // ================================================================
    // Error display
    // ================================================================

    #[test]
    fn test_error_display_invalid_base58() {
        let msg = DecodeError::InvalidBase58.to_string();
        assert!(msg.contains("base58"));
    }

    #[test]
    fn test_error_display_too_short() {
        let msg = DecodeError::TooShort.to_string();
        assert!(msg.contains("short"));
    }

    #[test]
    fn test_error_display_invalid_checksum() {
        let msg = DecodeError::InvalidChecksum.to_string();
        assert!(msg.contains("checksum"));
    }

    #[test]
    fn test_error_display_invalid_version() {
        let err = DecodeError::InvalidVersion {
            expected: 0x05,
            found: 0x10,
        };
        let msg = err.to_string();
        assert!(msg.contains("0x05"));
        assert!(msg.contains("0x10"));
    }

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

    // ================================================================
    // Cross-check: encode vs encode_raw consistency
    // ================================================================

    #[test]
    fn test_encode_matches_encode_raw() {
        let version = version::STATE_HASH;
        let payload = b"hello";
        let via_encode = encode(version, payload);

        let mut raw = vec![version];
        raw.extend_from_slice(payload);
        let via_raw = encode_raw(&raw);

        assert_eq!(via_encode, via_raw);
    }

    #[test]
    fn test_decode_matches_decode_raw() {
        let b58 = encode(version::STATE_HASH, b"hello");

        let (ver, payload) = decode(&b58).unwrap();
        let raw = decode_raw(&b58).unwrap();

        assert_eq!(raw[0], ver);
        assert_eq!(&raw[1..], &payload[..]);
    }
}
