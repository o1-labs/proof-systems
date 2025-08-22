pub mod transaction;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use mina_hasher::{Hashable, ROInput};
use mina_signer::{self, BaseField, Keypair, NetworkId, PubKey, ScalarField, SecKey, Signer};
use num_bigint::BigUint;
use rand::RngCore;
pub use transaction::Transaction;

enum TransactionType {
    PaymentTx,
    DelegationTx,
}

macro_rules! assert_sign_verify_tx {
    ($tx_type:expr, $sec_key:expr, $source_address:expr, $receiver_address:expr, $amount:expr, $fee:expr,
     $nonce:expr, $valid_until:expr, $memo:expr, $testnet_target:expr, $mainnet_target:expr) => {
        let kp = Keypair::from_hex($sec_key).expect("failed to create keypair");
        assert_eq!(
            kp.public,
            PubKey::from_address($source_address).expect("invalid source address")
        );
        let mut tx = match $tx_type {
            TransactionType::PaymentTx => Transaction::new_payment(
                PubKey::from_address($source_address).expect("invalid source address"),
                PubKey::from_address($receiver_address).expect("invalid receiver address"),
                $amount,
                $fee,
                $nonce,
            ),
            TransactionType::DelegationTx => Transaction::new_delegation(
                PubKey::from_address($source_address).expect("invalid source address"),
                PubKey::from_address($receiver_address).expect("invalid receiver address"),
                $fee,
                $nonce,
            ),
        };

        tx = tx.set_valid_until($valid_until).set_memo_str($memo);

        // TODO only one context
        let mut testnet_ctx = mina_signer::create_legacy(NetworkId::TESTNET);
        let mut mainnet_ctx = mina_signer::create_legacy(NetworkId::MAINNET);
        let testnet_sig = testnet_ctx.sign(&kp, &tx, false);
        let mainnet_sig = mainnet_ctx.sign(&kp, &tx, false);

        // Signing checks
        assert_ne!(testnet_sig, mainnet_sig); // Testnet and mainnet sigs are not equal
        assert_eq!(testnet_sig.to_string(), $testnet_target); // Testnet target check
        assert_eq!(mainnet_sig.to_string(), $mainnet_target); // Mainnet target check

        // Verification checks
        assert_eq!(testnet_ctx.verify(&testnet_sig, &kp.public, &tx), true);
        assert_eq!(mainnet_ctx.verify(&mainnet_sig, &kp.public, &tx), true);

        assert_eq!(mainnet_ctx.verify(&testnet_sig, &kp.public, &tx), false);
        assert_eq!(testnet_ctx.verify(&mainnet_sig, &kp.public, &tx), false);

        tx.valid_until = !tx.valid_until;
        assert_eq!(mainnet_ctx.verify(&testnet_sig, &kp.public, &tx), false);

        assert_eq!(testnet_ctx.verify(&mainnet_sig, &kp.public, &tx), false);
    };
}

#[test]
fn signer_test_raw() {
    let kp = Keypair::from_hex("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718")
        .expect("failed to create keypair");
    let tx = Transaction::new_payment(
        kp.public.clone(),
        PubKey::from_address("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt")
            .expect("invalid address"),
        1729000000000,
        2000000000,
        16,
    )
    .set_valid_until(271828)
    .set_memo_str("Hello Mina!");

    assert_eq!(tx.valid_until, 271828);
    assert_eq!(
        tx.memo,
        [
            0x01, 0x0b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x4d, 0x69, 0x6e, 0x61, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]
    );

    let mut ctx = mina_signer::create_legacy(NetworkId::TESTNET);
    let sig = ctx.sign(&kp, &tx, false);

    assert_eq!(sig.to_string(),
                "3043b286f5996fadf27a7f037ae6648b5f3282d537cde7f73e770b8ec8b6098a2055da539dcf904bf11b2332173f8d1b86720b7280eafa465c3972ee345208d2");
}

#[test]
fn signer_zero_test() {
    let kp = Keypair::from_hex("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718")
        .expect("failed to create keypair");
    let tx = Transaction::new_payment(
        kp.public.clone(),
        PubKey::from_address("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt")
            .expect("invalid address"),
        1729000000000,
        2000000000,
        16,
    );

    let mut ctx = mina_signer::create_legacy(NetworkId::TESTNET);
    let sig = ctx.sign(&kp, &tx, false);

    assert!(ctx.verify(&sig, &kp.public, &tx));

    // Zero some things
    let mut sig2 = sig.clone();
    sig2.rx = BaseField::zero();
    assert!(!ctx.verify(&sig2, &kp.public, &tx));
    let mut sig3 = sig;
    sig3.s = ScalarField::zero();
    assert!(!ctx.verify(&sig3, &kp.public, &tx));
    sig3.rx = BaseField::zero();
    assert!(!ctx.verify(&sig3, &kp.public, &tx));
}

#[test]
fn sign_payment_test_1() {
    assert_sign_verify_tx!(
        /* Transaction type   */ TransactionType::PaymentTx,
        /* sender secret key  */ "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
        /* source address     */ "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
        /* receiver address   */ "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
        /* amount             */ 1729000000000,
        /* fee                */ 2000000000,
        /* nonce              */ 16,
        /* valid until        */ 271828,
        /* memo               */ "Hello Mina!",
        /* testnet signature */ "3043b286f5996fadf27a7f037ae6648b5f3282d537cde7f73e770b8ec8b6098a2055da539dcf904bf11b2332173f8d1b86720b7280eafa465c3972ee345208d2",
        /* mainnet signature  */ "17ea50ada4b8cba16023cda7381e0b5c5383abffdaca5b29c638809fcab280213ee65f7f9a5bea9be80c17dd4dacfda2612be5ccbef312188cbdc07a7ba0cac8"
    );
}

#[test]
fn sign_payment_test_2() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::PaymentTx,
        /* sender secret key */ "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
        /* source address    */ "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4",
        /* receiver address  */ "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi",
        /* amount            */ 314159265359,
        /* fee               */ 1618033988,
        /* nonce             */ 0,
        /* valid until       */ 4294967295,
        /* memo              */ "",
        /* testnet signature */ "2d053885cd41cbd5128cdca6f892087243dc63a6884d6384d91d3725abfed6a91e526066e703e689a8c8d96ee5640462fc5682882de7c2955801949990fb7c46",
        /* mainnet signature */ "2419053e871888667477091bdbe8ea63095aab12058f527f15f0926b8315085e0300e298e73148f671e32ab7345c0251c122cc0c377cd4c9963b7a8419d3bb2b"
    );
}

#[test]
fn sign_payment_test_3() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::PaymentTx,
        /* sender secret key */ "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
        /* source address    */ "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4",
        /* receiver address  */ "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
        /* amount            */ 271828182845904,
        /* fee               */ 100000,
        /* nonce             */ 5687,
        /* valid until       */ 4294967295,
        /* memo              */ "01234567890123456789012345678901",
        /* testnet signature */ "0ccf1074823edd6060b432b94114392ebf09a3f59beb014ce01c6a6ef5248e891931b86d2b23ee2a365d2cc1169e0e9c79f14ac99946dea88073eaa380f71949",
        /* mainnet signature */ "0daa71681d0eb2a2609f6da1410b26f261712af5dfea37a28a75610d2357c78425b0bed8fdf0aa777b29b8360cd5678371fc81346f02a936dfd40c6579bc7a80"
    );
}

#[test]
fn sign_payment_test_4() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::PaymentTx,
        /* sender secret key */ "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
        /* source address    */ "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
        /* receiver address  */ "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
        /* amount            */ 0,
        /* fee               */ 2000000000,
        /* nonce             */ 0,
        /* valid until       */ 1982,
        /* memo              */ "",
        /* testnet signature */ "016605b969bc135983584f61b613a275e3f82246e33b647e9e36a788a444c26422bfa168c2bb35f60c652df76ef6e289f609f5ea2c0808b944b811870e3e22b4",
        /* mainnet signature */ "20b655894f4b904a963e233997e4f581808bfe65d960d5d08b6ec800e96a92ed375afe75bea1e0769acd119ec9585663ac58d30708e15a313a378bc6791284aa"
    );
}

#[test]
fn sign_delegation_test_1() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::DelegationTx,
        /* sender secret key */ "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
        /* source address    */ "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
        /* receiver address  */ "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
        /* amount            */ 0,
        /* fee               */ 2000000000,
        /* nonce             */ 16,
        /* valid until       */ 1337,
        /* memo              */ "Delewho?",
        /* testnet signature */ "2c824ef643a41c4612ba6a0c24ce846bed0ee777d7151e248c80a744039fdc9a0232fd582a8ce6d2835569e02dba417cc9bc5c2fb97bb75b9864a6a5eda793ca",
        /* mainnet signature */ "0c950860119ac6ebcb15caea9a844173ec3bbc568873b2b2b612ff2af20f736a1e0a2ba404da4629b6a282620e27d87b149b24edf9690c8770597ca436703bf3"
    );
}

#[test]
fn sign_delegation_test_2() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::DelegationTx,
        /* sender secret key */ "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
        /* source address    */ "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M",
        /* receiver address  */ "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
        /* amount            */ 0,
        /* fee               */ 2000000000,
        /* nonce             */ 0,
        /* valid until       */ 4294967295,
        /* memo              */ "",
        /* testnet signature */ "05976ab6942a47947adb10a5efa5abd0c2243355e048561ba96bb6d5018a83dc38357aa49be01e0870d6cf5104d67e463fb893e77aae60f8f20b8b959e00c876",
        /* mainnet signature */ "1aca6a2c25f5ea3613f2f1c667e4387389202ef61d0c707211ce752aa5d3952439afa9aad0e2552fb6b1287329a8645e0b607e97d1baa206a25143cf65120eeb"
    );
}

#[test]
fn sign_delegation_test_3() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::DelegationTx,
        /* sender secret key */ "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
        /* source address    */ "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4",
        /* receiver address  */ "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M",
        /* amount            */ 0,
        /* fee               */ 42000000000,
        /* nonce             */ 1,
        /* valid until       */ 4294967295,
        /* memo              */ "more delegates, more fun........",
        /* testnet signature */ "36a2d0f90691277472f7e541e27041e52a9a854f10aebf98e692dcd19ab7b9160d8c69d3fb5493cb79eb9c15076ce2c7ac1039424b6eef0958788e8ac0f12192",
        /* mainnet signature */ "18a0b829e18b8c3a9b2c5253be76059933e3ef56f0edab1ca145471139d94b7826c761c56eb118c535a9a1e705c9b3d13deb6ebe849ef9ee3b07e6e121af0a0d"
    );
}

#[test]
fn sign_delegation_test_4() {
    assert_sign_verify_tx!(
        /* Transaction type  */ TransactionType::DelegationTx,
        /* sender secret key */ "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
        /* source address    */ "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi",
        /* receiver address  */ "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
        /* amount            */ 0,
        /* fee               */ 1202056900,
        /* nonce             */ 0,
        /* valid until       */ 577216,
        /* memo              */ "",
        /* testnet signature */ "358ce127f348f39f6a0ee759696ed8c23987d7026d719706953014cdbbc8131b2f5cc547123a30720c2b7eb2abab2ee0971b82cb51288a26ffd2068f9515a38f",
        /* mainnet signature */ "09294417d4886cbb3e17aea3b84827677b39b80d7beda72f66b72e1d09e4dd6a2917d064697d643d869a1951911387bef5e1754e6cde5281dd61047c91dc1fcd"
    );
}

#[derive(Clone)]
struct Input {
    fields: Vec<BaseField>,
}

impl Hashable for Input {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();
        for field in &self.fields {
            roi = roi.append_field(*field);
        }
        roi
    }

    fn domain_string(network_id: NetworkId) -> Option<String> {
        // Domain strings must have length <= 20
        match network_id {
            NetworkId::MAINNET => "MinaSignatureMainnet",
            NetworkId::TESTNET => "CodaSignature*******",
        }
        .to_string()
        .into()
    }
}

#[test]
fn sign_fields_test() {
    let kp = Keypair::from_secret_key(
        SecKey::from_base58("EKFXH5yESt7nsD1TJy5WNb4agVczkvzPRVexKQ8qYdNqauQRA8Ef")
            .expect("failed to create secret key"),
    )
    .expect("failed to create keypair");

    let input = Input {
        fields: vec![BaseField::from(1), BaseField::from(2), BaseField::from(3)],
    };

    let mut testnet_ctx = mina_signer::create_kimchi::<Input>(NetworkId::TESTNET);
    let mut mainnet_ctx = mina_signer::create_kimchi::<Input>(NetworkId::MAINNET);

    let testnet_sig = testnet_ctx.sign(&kp, &input, true);
    let mainnet_sig = mainnet_ctx.sign(&kp, &input, true);

    assert_eq!(
        testnet_sig.rx.to_string(),
        "20765817320000234273433345899587917625188885976914380365037035465312392849949"
    );
    assert_eq!(
        testnet_sig.s.to_string(),
        "1002418623751815063744079415040141105602079382674393704838141255389705661040"
    );
    assert_eq!(
        mainnet_sig.rx.to_string(),
        "10877800556133241279092798070541266482295945495262263128372065874115589660865"
    );
    assert_eq!(
        mainnet_sig.s.to_string(),
        "7997465488592693587273287555462893250665854535708979748937792736327059812287"
    );
    assert!(testnet_ctx.verify(&testnet_sig, &kp.public, &input));
    assert!(mainnet_ctx.verify(&mainnet_sig, &kp.public, &input));
}

#[test]
fn test_signer_from_secret_key() {
    let kp = Keypair::from_secret_key(
        SecKey::from_hex("40000000000000000000000000000000224698FC0954F03125F7292BAAAAAAAB")
            .expect("failed to create secret key"),
    )
    .expect("failed to create keypair");

    let input = Input {
        fields: vec![BaseField::from(1), BaseField::from(2), BaseField::from(3)],
    };

    let mut testnet_ctx = mina_signer::create_kimchi::<Input>(NetworkId::TESTNET);
    let mut mainnet_ctx = mina_signer::create_kimchi::<Input>(NetworkId::MAINNET);

    let testnet_sig = testnet_ctx.sign(&kp, &input, true);
    let mainnet_sig = mainnet_ctx.sign(&kp, &input, true);

    assert!(testnet_ctx.verify(&testnet_sig, &kp.public, &input));
    assert!(mainnet_ctx.verify(&mainnet_sig, &kp.public, &input));
}

#[test]
fn test_scalar_to_base_field_overflow() {
    // Test the potential issue where the secret key is larger than the base
    // field modulus could cause problems in derive_nonce_compatible when
    // converting scalar to base field via BaseField::from(scalar.into_bigint())
    // There are 86663725065984043395317760 values between the two moduli.
    // Base: 28948022309329048855892746252171976963363056481941560715954676764349967630337
    // Scalar: 28948022309329048855892746252171976963363056481941647379679742748393362948097

    let mut rng = o1_utils::tests::make_test_rng(None);
    let scalar_field_modulus: BigUint = BigUint::from_bytes_le(&ScalarField::MODULUS.to_bytes_le());

    // Create a scalar field element close to its modulus
    // This test ensures that we can handle large scalar values, larger than the
    // base field modulus
    // Smaller than the difference between the two moduli
    let diff = rng.next_u64();
    let scalar_field_modulus_minus_diff: BigUint =
        scalar_field_modulus.clone() - BigUint::from(diff);

    // Create a keypair with a large scalar value to test derive_nonce_compatible
    let large_secret = SecKey::new(scalar_field_modulus_minus_diff.into());
    let kp = Keypair::from_secret_key(large_secret).unwrap();

    let input = Input {
        fields: vec![BaseField::from(1), BaseField::from(2), BaseField::from(3)],
    };

    let mut testnet_ctx = mina_signer::create_kimchi::<Input>(NetworkId::TESTNET);

    // This should not panic even with large scalar values
    let sig = testnet_ctx.sign(&kp, &input, true);

    // Verify the signature is valid
    assert!(testnet_ctx.verify(&sig, &kp.public, &input));
}

#[test]
fn test_base_field_modulus_minus_one_works() {
    // Complementary test to test_scalar_to_base_field_overflow to ensure that
    // the base field modulus minus one works correctly

    let base_field_modulus: BigUint = BigUint::from_bytes_le(&BaseField::MODULUS.to_bytes_le());

    // Create a scalar field element close to its modulus
    // This test ensures that we can handle large scalar values, larger than the
    // base field modulus
    // Smaller than the difference between the two moduli
    let base_field_modulus_minus_one: BigUint = base_field_modulus.clone() - BigUint::one();

    // Create a keypair with a large scalar value to test derive_nonce_compatible
    let large_secret = SecKey::new(base_field_modulus_minus_one.into());
    let kp = Keypair::from_secret_key(large_secret).unwrap();

    let input = Input {
        fields: vec![BaseField::from(1), BaseField::from(2), BaseField::from(3)],
    };

    let mut testnet_ctx = mina_signer::create_kimchi::<Input>(NetworkId::TESTNET);

    // This should not panic even with large scalar values
    let sig = testnet_ctx.sign(&kp, &input, true);

    // Verify the signature is valid
    assert!(testnet_ctx.verify(&sig, &kp.public, &input));
}
