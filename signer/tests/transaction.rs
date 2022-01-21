use mina_signer::{CompressedPubKey, Hashable, NetworkId, PubKey, ROInput, Signable};

const MEMO_BYTES: usize = 34;
const TAG_BITS: usize = 3;
const PAYMENT_TX_TAG: [bool; TAG_BITS] = [false, false, false];
const DELEGATION_TX_TAG: [bool; TAG_BITS] = [false, false, true];

#[derive(Clone, Copy)]
pub struct Transaction {
    // Common
    pub fee: u64,
    pub fee_token: u64,
    pub fee_payer_pk: CompressedPubKey,
    pub nonce: u32,
    pub valid_until: u32,
    pub memo: [u8; MEMO_BYTES],
    // Body
    pub tag: [bool; TAG_BITS],
    pub source_pk: CompressedPubKey,
    pub receiver_pk: CompressedPubKey,
    pub token_id: u64,
    pub amount: u64,
    pub token_locked: bool,
}

impl Hashable for Transaction {
    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_field(self.fee_payer_pk.x);
        roi.append_field(self.source_pk.x);
        roi.append_field(self.receiver_pk.x);

        roi.append_u64(self.fee);
        roi.append_u64(self.fee_token);
        roi.append_bit(self.fee_payer_pk.is_odd);
        roi.append_u32(self.nonce);
        roi.append_u32(self.valid_until);
        roi.append_bytes(&self.memo);

        for tag_bit in self.tag {
            roi.append_bit(tag_bit);
        }

        roi.append_bit(self.source_pk.is_odd);
        roi.append_bit(self.receiver_pk.is_odd);
        roi.append_u64(self.token_id);
        roi.append_u64(self.amount);
        roi.append_bit(self.token_locked);

        roi
    }
}

impl Signable for Transaction {
    fn domain_string(network_id: NetworkId) -> &'static str {
        // Domain strings must have length <= 20
        match network_id {
            NetworkId::MAINNET => "MinaSignatureMainnet",
            NetworkId::TESTNET => "CodaSignature",
        }
    }
}

impl Transaction {
    pub fn new_payment(from: PubKey, to: PubKey, amount: u64, fee: u64, nonce: u32) -> Self {
        Transaction {
            fee: fee,
            fee_token: 1,
            fee_payer_pk: from.into_compressed(),
            nonce: nonce,
            valid_until: u32::MAX,
            memo: array_init::array_init(|i| (i == 0) as u8),
            tag: PAYMENT_TX_TAG,
            source_pk: from.into_compressed(),
            receiver_pk: to.into_compressed(),
            token_id: 1,
            amount: amount,
            token_locked: false,
        }
    }

    pub fn new_delegation(from: PubKey, to: PubKey, fee: u64, nonce: u32) -> Self {
        Transaction {
            fee: fee,
            fee_token: 1,
            fee_payer_pk: from.into_compressed(),
            nonce: nonce,
            valid_until: u32::MAX,
            memo: array_init::array_init(|i| (i == 0) as u8),
            tag: DELEGATION_TX_TAG,
            source_pk: from.into_compressed(),
            receiver_pk: to.into_compressed(),
            token_id: 1,
            amount: 0,
            token_locked: false,
        }
    }

    pub fn set_valid_until(mut self, global_slot: u32) -> Self {
        self.valid_until = global_slot;

        self
    }

    pub fn set_memo(mut self, memo: [u8; MEMO_BYTES - 2]) -> Self {
        self.memo[0] = 0x01;
        self.memo[1] = (MEMO_BYTES - 2) as u8;
        self.memo[2..].copy_from_slice(&memo[..]);

        self
    }

    pub fn set_memo_str(mut self, memo: &str) -> Self {
        self.memo[0] = 0x01;
        self.memo[1] = std::cmp::min(memo.len(), MEMO_BYTES - 2) as u8;
        let memo = format!("{:\0<32}", memo); // Pad user-supplied memo with zeros
        self.memo[2..]
            .copy_from_slice(&memo.as_bytes()[..std::cmp::min(memo.len(), MEMO_BYTES - 2)]);
        // Anything beyond MEMO_BYTES is truncated

        self
    }
}

use mina_signer::Keypair;

#[test]
fn transaction_domain() {
    assert_eq!(
        Transaction::domain_string(NetworkId::MAINNET),
        "MinaSignatureMainnet"
    );
    assert_eq!(
        Transaction::domain_string(NetworkId::TESTNET),
        "CodaSignature"
    );
}

#[test]
fn transaction_memo() {
    let kp = Keypair::from_hex("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718")
        .expect("failed to create keypair");

    let tx = Transaction::new_payment(kp.public, kp.public, 0, 0, 0);
    assert_eq!(
        tx.memo,
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0
        ]
    );

    // Memo length < max memo length
    let tx = tx.set_memo([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ]);
    assert_eq!(
        tx.memo,
        [
            1, 32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ]
    );

    // Memo > max memo length (truncate)
    let tx = tx.set_memo([
        8, 92, 15, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 2, 31, 54, 55, 4, 57, 48, 49, 50,
        51, 52, 53, 54, 55, 6, 71, 48, 49,
    ]);
    assert_eq!(
        tx.memo,
        [
            1, 32, 8, 92, 15, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 2, 31, 54, 55, 4, 57, 48,
            49, 50, 51, 52, 53, 54, 55, 6, 71, 48, 49
        ]
    );
}

#[test]
fn transaction_memo_str() {
    let kp = Keypair::from_hex("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718")
        .expect("failed to create keypair");

    let tx = Transaction::new_payment(kp.public, kp.public, 0, 0, 0);
    assert_eq!(
        tx.memo,
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0
        ]
    );

    // Memo length < max memo length
    let tx = tx.set_memo_str("Hello Mina!");
    assert_eq!(
        tx.memo,
        [
            1, 11, 72, 101, 108, 108, 111, 32, 77, 105, 110, 97, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );

    // Memo > max memo length (truncate)
    let tx = tx.set_memo_str("012345678901234567890123456789012345");
    assert_eq!(
        tx.memo,
        [
            1, 32, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49
        ]
    );
}
