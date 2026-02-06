use mina_base58::{decode, decode_raw, encode_raw, DecodeError};

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
    let valid =
        "3NLx3eBDTvYmP27bUmYANzmhjL5rGe36nGW6N5XhGcuStF6Zv7ZD";
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
    let valid =
        "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV";
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
    assert!(
        err == DecodeError::InvalidBase58
            || err == DecodeError::TooShort
    );
}

#[test]
fn test_decode_raw_invalid_base58() {
    assert_eq!(
        decode_raw("0OIl").unwrap_err(),
        DecodeError::InvalidBase58
    );
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
