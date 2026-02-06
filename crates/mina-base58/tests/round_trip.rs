use mina_base58::{
    decode, decode_raw, decode_version, encode, encode_raw, version,
};

#[test]
fn test_encode_raw_decode_raw_roundtrip() {
    let raw = b"\x10\x01\x02\x03some data";
    let encoded = encode_raw(raw);
    let decoded = decode_raw(&encoded).unwrap();
    assert_eq!(decoded, raw);
}

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
fn test_secret_key_roundtrip_versioned() {
    let b58 = "EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodY";
    let payload = decode_version(b58, version::SECRET_KEY).unwrap();
    assert_eq!(encode(version::SECRET_KEY, &payload), b58);
}

#[test]
fn test_secret_key_roundtrip_raw() {
    let b58 = "EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodY";
    let raw = decode_raw(b58).unwrap();
    assert_eq!(raw[0], version::SECRET_KEY);
    assert_eq!(encode_raw(&raw), b58);
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

#[test]
fn test_address_roundtrip() {
    let expected = "B62qkUHaJUHERZuCHQhXCQ8xsGBqyYSgjQsKnKN5HhSJecakuJ4pYyk";
    let (ver, payload) = decode(expected).unwrap();
    assert_eq!(ver, version::NON_ZERO_CURVE_POINT_COMPRESSED);
    assert_eq!(encode(ver, &payload), expected);
}

#[test]
fn test_ledger_hash_roundtrip() {
    let expected = "jwrPvAMUNo3EKT2puUk5Fxz6B7apRAoKNTGpAA49t3TRSfzvdrL";
    let (ver, payload) = decode(expected).unwrap();
    assert_eq!(ver, version::LEDGER_HASH);
    assert_eq!(encode(ver, &payload), expected);
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
