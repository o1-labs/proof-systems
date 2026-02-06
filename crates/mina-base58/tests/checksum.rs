use mina_base58::checksum;

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
