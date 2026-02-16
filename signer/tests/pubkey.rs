use mina_signer::{pubkey::PubKeyError, CompressedPubKey, PubKey, SecKey};

#[test]
fn test_from_hex() {
    assert_eq!(
            PubKey::to_hex(
                &PubKey::from_hex(
                    "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
                )
                .expect("failed to decode pub key"),
            ),
            "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
        );

    assert_eq!(
            PubKey::to_hex(
                &PubKey::from_hex(
                    "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
                )
                .expect("failed to decode pub key"),
            ),
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
        );

    assert_eq!(
            PubKey::from_hex("44100485d466a4c9f281d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"),
            Err(PubKeyError::XCoordinate)
        );

    assert_eq!(
            PubKey::from_hex("44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168715883c"),
            Err(PubKeyError::NonCurvePoint)
        );

    assert_eq!(
        PubKey::from_hex("z8f71009a6502f89a469a037f14e97386034ea3855877159f29f4a532a2e5f28"),
        Err(PubKeyError::Hex)
    );

    assert_eq!(
            PubKey::from_hex("44100485d466a4c9f481d43be9a6d4aa5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"),
            Err(PubKeyError::Hex)
        );
}

#[test]
fn test_from_secret_key() {
    assert_eq!(PubKey::from_secret_key(
                &SecKey::from_hex("090dd91a2505081a158782c5a24fef63f326749b383423c29827e465f7ca262b").expect("failed to decode sec key")
            ).expect("failed to decode pub key").to_hex(),
            "3f8c32817851b7c1ad99495463ef5e99c3b3240524f0df3ff7fc41181d849e0086fa821d54de15c523a840c5f62df90aeabb1097b85c6a88e163e9d74e505803"
        );

    assert_eq!(PubKey::from_secret_key(
                &SecKey::from_hex("086d78e0e5deb62daeef8e3a5574d52a3d3bff5281b4dd49140564c7d80468c9").expect("failed to decode sec key")
            ).expect("failed to decode pub key").to_hex(),
            "666c450f5e888d3b2341d77b32cb6d0cd4912829ea9c41030d1fd2baff6b9a30c267208638544299e8d369e80b25a24bdd07383b6ea908028d9a406b528d4a01"
        );

    assert_eq!(PubKey::from_secret_key(
                &SecKey::from_hex("0859771e9394e96dd6d01d57ef074dc25313e63bd331fa5478a9fed9e24855a0").expect("failed to decode sec key")
            ).expect("failed to decode pub key").to_hex(),
            "6ed0776ab11e3dd3b637cce03a90529e518220132f1a61dd9c0d50aa998abf1d2f43c0f1eb73888ef6f7dac4d7094d3c92cd67abab39b828c5f10aff0b6a0002"
        );
}

#[test]
fn test_from_address() {
    macro_rules! assert_from_address_check {
        ($address:expr) => {
            let pk = PubKey::from_address($address).expect("failed to create pubkey");
            assert_eq!(pk.into_address(), $address);
        };
    }

    assert_from_address_check!("B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV");
    assert_from_address_check!("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt");
    assert_from_address_check!("B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4");
    assert_from_address_check!("B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi");
    assert_from_address_check!("B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N");
    assert_from_address_check!("B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M");
}

#[test]
fn test_to_bytes() {
    let mut bytes = vec![
        68, 16, 4, 133, 212, 102, 164, 201, 244, 129, 212, 59, 233, 166, 212, 169, 165, 233, 122,
        218, 193, 151, 119, 177, 75, 107, 122, 129, 237, 238, 57, 9, 49, 121, 244, 241, 40, 151,
        121, 124, 254, 120, 191, 47, 214, 50, 31, 54, 176, 11, 208, 89, 45, 239, 191, 57, 161, 153,
        180, 22, 135, 53, 136, 60,
    ];
    assert_eq!(
        PubKey::from_bytes(&bytes)
            .expect("failed to decode pub key")
            .to_bytes(),
        bytes
    );

    bytes[0] = 0; // negative test: invalid curve point
    assert_eq!(PubKey::from_bytes(&bytes), Err(PubKeyError::NonCurvePoint));

    bytes[0] = 68;
    let mut bytes = [bytes, vec![255u8, 102u8]].concat(); // negative test: to many bytes
    assert_eq!(
        PubKey::from_bytes(&bytes),
        Err(PubKeyError::YCoordinateBytes)
    );

    bytes.remove(0); // negative test: to few bytes
    bytes.remove(0);
    assert_eq!(
        PubKey::from_bytes(&bytes),
        Err(PubKeyError::XCoordinateBytes)
    );
}

#[test]
fn test_compressed_from_hex() {
    assert_eq!(PubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
            ).expect("failed to decode pub key").into_address(),
            CompressedPubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee390901"
            ).expect("failed to decode compressed pub key").into_address()
        );

    assert_eq!(PubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee390901"
            ).expect("failed to decode compressed pub key")
        );

    assert_ne!(PubKey::from_hex(
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee39093179f4f12897797cfe78bf2fd6321f36b00bd0592defbf39a199b4168735883c"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex( // Invalid parity bit
                "44100485d466a4c9f481d43be9a6d4a9a5e97adac19777b14b6b7a81edee390900"
            ).expect("failed to decode compressed pub key")
        );

    assert_eq!(PubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2900"
            ).expect("failed to decode compressed pub key")
        );

    assert_eq!(
        CompressedPubKey::from_hex(
            // Missing parity bit
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29"
        ),
        Err(PubKeyError::YCoordinateParityBytes)
    );

    assert_eq!(
        CompressedPubKey::from_hex(
            // Wrong parity bytes
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a290101"
        ),
        Err(PubKeyError::YCoordinateParityBytes)
    );

    assert_eq!(
        CompressedPubKey::from_hex(
            // Invalid parity byte
            "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2902"
        ),
        Err(PubKeyError::YCoordinateParity)
    );

    assert!(CompressedPubKey::from_hex(
        // OK parity byte (odd)
        "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2900"
    )
    .is_ok());

    assert!(CompressedPubKey::from_hex(
        // OK parity byte (odd)
        "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2901"
    )
    .is_ok());

    assert_ne!(PubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a29125030f6cd465cccf2ebbaabc397a6823932bc55dc1ddf9954c9e78da07c0928"
            ).expect("failed to decode pub key").into_compressed(),
            CompressedPubKey::from_hex(
                "0c18d735252f4401eb845d08a87d780e9dc6ed053d0e071395277f0a34d45a2901"
            ).expect("failed to decode compressed pub key")
        );
}

#[test]
fn test_compressed_to_bytes() {
    let mut bytes = vec![
        68, 16, 4, 133, 212, 102, 164, 201, 244, 129, 212, 59, 233, 166, 212, 169, 165, 233, 122,
        218, 193, 151, 119, 177, 75, 107, 122, 129, 237, 238, 57, 9, 1,
    ];
    assert_eq!(
        CompressedPubKey::from_bytes(&bytes)
            .expect("failed to decode pub key")
            .to_bytes(),
        bytes
    );

    bytes[4] = 73; // negative test: invalid x
    assert_eq!(
        CompressedPubKey::from_bytes(&bytes),
        Err(PubKeyError::XCoordinate)
    );

    bytes[0] = 212;
    let mut bytes = [bytes, vec![255u8]].concat(); // negative test: to many bytes
    assert_eq!(
        CompressedPubKey::from_bytes(&bytes),
        Err(PubKeyError::YCoordinateParityBytes)
    );

    bytes.remove(0); // negative test: to few bytes
    bytes.remove(0);
    assert_eq!(
        CompressedPubKey::from_bytes(&bytes),
        Err(PubKeyError::XCoordinateBytes)
    );
}
