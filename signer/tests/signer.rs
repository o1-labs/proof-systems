pub mod transaction;
use ark_ff::Zero;
use mina_signer::{self, BaseField, Keypair, NetworkId, PubKey, ScalarField, Signer};
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
        let testnet_sig = testnet_ctx.sign(&kp, &tx);
        let mainnet_sig = mainnet_ctx.sign(&kp, &tx);

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
    let sig = ctx.sign(&kp, &tx);

    assert_eq!(sig.to_string(),
                "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af");
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
    let sig = ctx.sign(&kp, &tx);

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
        /* testntet signature */ "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af",
        /* mainnet signature  */ "124c592178ed380cdffb11a9f8e1521bf940e39c13f37ba4c55bb4454ea69fba3c3595a55b06dac86261bb8ab97126bf3f7fff70270300cb97ff41401a5ef789"
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
        /* testnet signature */ "23a9e2375dd3d0cd061e05c33361e0ba270bf689c4945262abdcc81d7083d8c311ae46b8bebfc98c584e2fb54566851919b58cf0917a256d2c1113daa1ccb27f",
        /* mainnet signature */ "204eb1a37e56d0255921edd5a7903c210730b289a622d45ed63a52d9e3e461d13dfcf301da98e218563893e6b30fa327600c5ff0788108652a06b970823a4124"
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
        /* testnet signature */ "2b4d0bffcb57981d11a93c05b17672b7be700d42af8496e1ba344394da5d0b0b0432c1e8a77ee1bd4b8ef6449297f7ed4956b81df95bdc6ac95d128984f77205",
        /* mainnet signature */ "076d8ebca8ccbfd9c8297a768f756ff9d08c049e585c12c636d57ffcee7f6b3b1bd4b9bd42cc2cbee34b329adbfc5127fe5a2ceea45b7f55a1048b7f1a9f7559"
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
        /* testnet signature */ "25bb730a25ce7180b1e5766ff8cc67452631ee46e2d255bccab8662e5f1f0c850a4bb90b3e7399e935fff7f1a06195c6ef89891c0260331b9f381a13e5507a4c",
        /* mainnet signature */ "058ed7fb4e17d9d400acca06fe20ca8efca2af4ac9a3ed279911b0bf93c45eea0e8961519b703c2fd0e431061d8997cac4a7574e622c0675227d27ce2ff357d9"
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
        /* testnet signature */ "30797d7d0426e54ff195d1f94dc412300f900cc9e84990603939a77b3a4d2fc11ebab12857b47c481c182abe147279732549f0fd49e68d5541f825e9d1e6fa04",
        /* mainnet signature */ "0904e9521a95334e3f6757cb0007ec8af3322421954255e8d263d0616910b04d213344f8ec020a4b873747d1cbb07296510315a2ec76e52150a4c765520d387f"
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
        /* testnet signature */ "07e9f88fc671ed06781f9edb233fdbdee20fa32303015e795747ad9e43fcb47b3ce34e27e31f7c667756403df3eb4ce670d9175dd0ae8490b273485b71c56066",
        /* mainnet signature */ "2406ab43f8201bd32bdd81b361fdb7871979c0eec4e3b7a91edf87473963c8a4069f4811ebc5a0e85cbb4951bffe93b638e230ce5a250cb08d2c250113a1967c"
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
        /* testnet signature */ "1ff9f77fed4711e0ebe2a7a46a7b1988d1b62a850774bf299ec71a24d5ebfdd81d04a570e4811efe867adefe3491ba8b210f24bd0ec8577df72212d61b569b15",
        /* mainnet signature */ "36a80d0421b9c0cbfa08ea95b27f401df108b30213ae138f1f5978ffc59606cf2b64758db9d26bd9c5b908423338f7445c8f0a07520f2154bbb62926aa0cb8fa"
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
        /* testnet signature */ "26ca6b95dee29d956b813afa642a6a62cd89b1929320ed6b099fd191a217b08d2c9a54ba1c95e5000b44b93cfbd3b625e20e95636f1929311473c10858a27f09",
        /* mainnet signature */ "093f9ef0e4e051279da0a3ded85553847590ab739ee1bfd59e5bb30f98ed8a001a7a60d8506e2572164b7a525617a09f17e1756ac37555b72e01b90f37271595"
    );
}
