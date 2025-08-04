use mina_signer::{keypair::KeypairError, seckey::SecKeyError, Keypair};

#[test]
fn test_from_hex() {
    assert_eq!(
        Keypair::from_hex(""),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
    );
    assert_eq!(
        Keypair::from_hex("1428fadcf0c02396e620f14f176fddb5d769b7de2027469d027a80142ef8f07"),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyHex))
    );
    assert_eq!(
        Keypair::from_hex("0f5314f176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyHex))
    );
    assert_eq!(
        Keypair::from_hex("g64244176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyHex))
    );
    assert_eq!(
        Keypair::from_hex("4244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718"),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
    );

    Keypair::from_hex("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718")
        .expect("failed to decode keypair secret key");
}

#[test]
fn test_get_address() {
    macro_rules! assert_get_address_eq {
        ($sec_key_hex:expr, $target_address:expr) => {
            let kp = Keypair::from_hex($sec_key_hex).expect("failed to create keypair");
            assert_eq!(kp.get_address(), $target_address);
        };
    }

    assert_get_address_eq!(
        "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
        "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV"
    );
    assert_get_address_eq!(
        "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e",
        "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt"
    );
    assert_get_address_eq!(
        "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
        "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi"
    );
    assert_get_address_eq!(
        "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
        "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N"
    );
    assert_get_address_eq!(
        "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
        "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M"
    );
    assert_get_address_eq!(
        "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
        "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4"
    );
}

#[test]
fn test_to_bytes() {
    let bytes = [
        61, 18, 244, 30, 36, 241, 5, 54, 107, 96, 154, 162, 58, 78, 242, 140, 186, 233, 25, 35,
        145, 119, 39, 94, 162, 123, 208, 202, 189, 29, 235, 209,
    ];
    assert_eq!(
        Keypair::from_bytes(&bytes)
            .expect("failed to decode keypair")
            .to_bytes(),
        bytes
    );

    // negative test (too many bytes)
    assert_eq!(
        Keypair::from_bytes(&[
            61, 18, 244, 30, 36, 241, 5, 54, 107, 96, 154, 162, 58, 78, 242, 140, 186, 233, 25, 35,
            145, 119, 39, 94, 162, 123, 208, 202, 189, 29, 235, 209, 0
        ]),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
    );

    // negative test (too few bytes)
    assert_eq!(
        Keypair::from_bytes(&[
            61, 18, 244, 30, 36, 241, 5, 54, 107, 96, 154, 162, 58, 78, 242, 140, 186, 233, 25, 35,
            145, 119, 39, 94, 162, 123, 208, 202, 189, 29
        ]),
        Err(KeypairError::SecretKey(SecKeyError::SecretKeyBytes))
    );
}
