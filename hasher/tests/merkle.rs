use ark_ff::Zero;
use mina_hasher::*;
use std::sync::RwLock;

lazy_static::lazy_static! {
    static ref DOMAIN_STRING_CALL_COUNTER: RwLock<usize> = RwLock::new(0);
}

#[derive(Debug, Clone)]
struct TestMerkleNode {
    height: u32,
    left: Fp,
    right: Fp,
}

impl Hashable for TestMerkleNode {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();
        roi.append_field(self.left);
        roi.append_field(self.right);
        roi
    }

    fn domain_string(this: Option<&Self>, _: Self::D) -> Option<String> {
        match this {
            None => format!("Unused").into(),
            Some(x) => {
                let mut counter = DOMAIN_STRING_CALL_COUNTER.write().unwrap();
                *counter += 1;
                format!("TestMerkleNode{:03}", x.height).into()
            }
        }
    }
}

#[test]
fn ensure_domain_string_is_invoked() {
    let node = TestMerkleNode {
        height: 3,
        left: Fp::zero(),
        right: Fp::zero(),
    };
    for i in 0..10 {
        let mut hasher = create_legacy(());
        hasher.hash(&node);
        let counter = DOMAIN_STRING_CALL_COUNTER.read().unwrap();
        assert_eq!(*counter, i + 1)
    }
}
