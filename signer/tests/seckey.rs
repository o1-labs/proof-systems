use mina_signer::{seckey::SecKeyError, SecKey};

#[test]
fn test_from_hex() {
    assert_eq!(
        SecKey::to_hex(
            &SecKey::from_hex("3d12f41e24f105366b609aa23a4ef28cbae919239177275ea27bd0cabd1debd1")
                .expect("failed to decode sec key"),
        ),
        "3d12f41e24f105366b609aa23a4ef28cbae919239177275ea27bd0cabd1debd1"
    );

    assert_eq!(
        SecKey::to_hex(
            &SecKey::from_hex("285f2e2a534a9ff25971875538ea346038974ef137a069a4892f50e60910f7d8")
                .expect("failed to decode sec key"),
        ),
        "285f2e2a534a9ff25971875538ea346038974ef137a069a4892f50e60910f7d8"
    );

    assert_eq!(
        SecKey::from_hex("d8f71009e6502f89a469a037f14e97386034ea3855877159f29f4a532a2e5f28"),
        Err(SecKeyError::SecretKeyBytes)
    );

    assert_eq!(
        SecKey::from_hex("d8f71009g6502f89a469a037f14e97386034ea3855877159f29f4a532a2e5f28"),
        Err(SecKeyError::SecretKeyHex)
    );
}

#[test]
fn test_to_bytes() {
    let bytes = [
        40, 95, 46, 42, 83, 74, 159, 242, 89, 113, 135, 85, 56, 234, 52, 96, 56, 151, 78, 241, 55,
        160, 105, 164, 137, 47, 80, 230, 9, 16, 247, 216,
    ];
    assert_eq!(
        SecKey::from_bytes(&bytes)
            .expect("failed to decode sec key")
            .to_bytes(),
        bytes
    );

    // negative test (too many bytes)
    assert_eq!(
        SecKey::from_bytes(&[
            40, 95, 46, 42, 83, 74, 159, 242, 89, 113, 135, 85, 56, 234, 52, 96, 56, 151, 78, 241,
            55, 160, 105, 164, 137, 47, 80, 230, 9, 16, 247, 216, 10
        ]),
        Err(SecKeyError::SecretKeyBytes)
    );

    // negative test (too few bytes)
    assert_eq!(
        SecKey::from_bytes(&[
            40, 95, 46, 42, 83, 74, 159, 242, 89, 113, 135, 85, 56, 234, 52, 96, 56, 151, 78, 241,
            55, 160, 105, 164, 137, 47, 80, 230, 9, 16, 247
        ]),
        Err(SecKeyError::SecretKeyBytes)
    );
}

#[test]
fn test_base58() {
    assert_eq!(
        SecKey::from_base58("EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodY")
            .expect("failed to decode sec key")
            .to_base58(),
        "EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodY"
    );

    // invalid checksum
    assert_eq!(
        SecKey::from_base58("EKFS3M4Fe1VkVjPMn2jauXa1Vv6w6gRES5oLbH3vZmP26uQESodZ"),
        Err(SecKeyError::SecretKeyChecksum)
    );

    // invalid version
    assert_eq!(
        SecKey::from_base58("ETq4cWR9pAQtUFQ8L78UhhfVkMJaw6gxbXRU9jQ24F8jPEh7tn3q"),
        Err(SecKeyError::SecretKeyVersion)
    );

    // invalid length
    assert_eq!(
        SecKey::from_base58("EKFS3M4Fe1VkVjPMn2a1Vv6w6gRES5oLbH3vZmP26uQESodY"),
        Err(SecKeyError::SecretKeyLength)
    );
}
