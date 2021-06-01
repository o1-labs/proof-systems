use algebra::{field_new, pasta, BigInteger256, BigInteger384, SquareRootField};

pub trait QnrField: SquareRootField {
    const QNR: Self;
}

impl QnrField for pasta::Fp {
    // 5
    const QNR: Self = field_new!(
        Self,
        BigInteger256([
            0xa1a55e68ffffffed,
            0x74c2a54b4f4982f3,
            0xfffffffffffffffd,
            0x3fffffffffffffff
        ])
    );
}

impl QnrField for pasta::Fq {
    // 5
    const QNR: Self = field_new!(
        Self,
        BigInteger256([
            0x96bc8c8cffffffed,
            0x74c2a54b49f7778e,
            0xfffffffffffffffd,
            0x3fffffffffffffff
        ])
    );
}
