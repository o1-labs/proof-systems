pub mod transaction;
use ark_ff::{One, Zero};
use mina_hasher::{Hashable, ROInput};
use mina_signer::{self, BaseField, Keypair, NetworkId, PubKey, ScalarField, SecKey, Signer};
use o1_utils::FieldHelpers;
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
fn test_signer_test_raw() {
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
                "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af");
}

#[test]
fn test_signer_zero_test() {
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
fn test_sign_payment_test_1() {
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
fn test_sign_payment_test_2() {
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
fn test_sign_payment_test_3() {
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
fn test_sign_payment_test_4() {
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
fn test_sign_delegation_test_1() {
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
fn test_sign_delegation_test_2() {
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
fn test_sign_delegation_test_3() {
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
fn test_sign_delegation_test_4() {
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

#[test]
fn test_poseidon_initial_state_network_legacy() {
    // Values in little-endian format. Depending on the library, you might need
    // to reverse the byte order.
    let exp_values_mainnet_le = [
        "0x9496a4a9d91dd6334b88384704786cfd52a0b0c76437d1db70470932ad22c237",
        "0x33d39cc6551071d976ad1643e429a088f7f156f8cf2867db92de1a5d53dfb810",
        "0xe4e6218a90a96df5f1d763eddc871eb859d53a018e371ec050c3c2aa94386100",
    ];
    let exp_values_testnet_le = [
        "0x9253c8b862b9075065c6f71e3d93177dfca9a2af0789276a3d2afeb31837323e",
        "0x994ee43d6a2c03d1548c24a0487daf64b964cb920cc5e5cca54037488b1c0a37",
        "0x360dc14633553dfd9c832db3318ee1d7514b719e48fbaeff1a912df003331c07",
    ];
    // Test that the initial state of the legacy hasher is correct for the
    // network
    {
        let hasher = mina_hasher::create_legacy::<Transaction>(NetworkId::MAINNET);
        let initial_state = hasher.state;
        // print in hexa for C code
        let initial_state_hex: Vec<String> = initial_state
            .iter()
            .map(|x| format!("0x{}", x.to_hex()))
            .collect();
        assert_eq!(initial_state_hex, exp_values_mainnet_le);
    }
    {
        let hasher = mina_hasher::create_legacy::<Transaction>(NetworkId::TESTNET);
        let initial_state = hasher.state;
        // print in hexa for C code
        let initial_state_hex: Vec<String> = initial_state
            .iter()
            .map(|x| format!("0x{}", x.to_hex()))
            .collect();
        assert_eq!(initial_state_hex, exp_values_testnet_le);
    }
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
fn test_poseidon_initial_state_network_kimchi() {
    // Values in little-endian format. Depending on the library, you might need
    // to reverse the byte order.
    let exp_values_mainnet_le = [
        "0x494a6a0c1b0d8ca7bc1cef37a3d69c4133b8a994e760c2ff5ba1a723a67e393f",
        "0x4c2561efcd3dd41998ac7f4b20d12d2947bb0c4177d7f4e6a7753ccc78a4ce1c",
        "0xfbabea66d176d79be0265717a2ee07e019a7f9fe0638b128472fe9ed93e12305",
    ];
    let exp_values_testnet_le = [
        "0x486a7ac50b48d60b4e844cdeac2aa487b85c68720d93bd64043bc1f839f7790e",
        "0xf1a03a60a27687f42330c6cf91acad27ad12b1739f229ba5c2b7f1debf171031",
        "0x1dfa8ba1eab55bbb8c3912f2f9c5a323fc8583af0979a499d5c4dc59b3a1f521",
    ];
    // Test that the initial state of the legacy hasher is correct for the network
    {
        let hasher = mina_hasher::create_kimchi::<Transaction>(NetworkId::MAINNET);
        let initial_state = hasher.state;
        // print in hexa for C code
        let initial_state_hex: Vec<String> = initial_state
            .iter()
            .map(|x| format!("0x{}", x.to_hex()))
            .collect();
        assert_eq!(initial_state_hex, exp_values_mainnet_le);
    }
    {
        let hasher = mina_hasher::create_kimchi::<Transaction>(NetworkId::TESTNET);
        let initial_state = hasher.state;
        // print in hexa for C code
        let initial_state_hex: Vec<String> = initial_state
            .iter()
            .map(|x| format!("0x{}", x.to_hex()))
            .collect();
        assert_eq!(initial_state_hex, exp_values_testnet_le);
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
