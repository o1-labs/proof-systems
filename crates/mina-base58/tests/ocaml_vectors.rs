mod helpers;

use mina_base58::{decode, decode_version, encode, version, DecodeError};

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
    let corrupted = helpers::corrupt_last_char(&encoded);
    assert_eq!(
        decode(&corrupted).unwrap_err(),
        DecodeError::InvalidChecksum
    );
}

#[test]
fn test_ocaml_invalid_length() {
    // "abcd" in base58 decodes to 3 bytes, below the 5-byte minimum
    assert_eq!(decode("abcd").unwrap_err(), DecodeError::TooShort);
}

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
