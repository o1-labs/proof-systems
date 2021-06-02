use algebra::{bn_382, field_new, tweedle, BigInteger256, BigInteger384, SquareRootField};
use curves::pasta;

pub trait QnrField: SquareRootField {
    const QNR: Self;
}

impl QnrField for bn_382::Fp {
    // 7
    const QNR: Self = field_new!(
        Self,
        BigInteger384([
            0xffffffffffffffcf,
            0xffffffb67daf6367,
            0xdc87071c715188df,
            0x718ba6243a5346c8,
            0x4fa46fc531ce56d5,
            0x1b21bac71c8e0dbc
        ])
    );
}

impl QnrField for bn_382::Fq {
    // 7
    const QNR: Self = field_new!(
        Self,
        BigInteger384([
            0xffffffffffffffcf,
            0xffffffb67daf6367,
            0x7b5eb425ec6cb67f,
            0x718ba6243a5346b6,
            0x4fa46fc531ce56d5,
            0x1b21bac71c8e0dbc
        ])
    );
}

impl QnrField for tweedle::Fp {
    // 5
    const QNR: Self = field_new!(
        Self,
        BigInteger256([
            0x8388339ffffffed,
            0xbcb60a12f74c5739,
            0xffffffffffffffff,
            0x3fffffffffffffff
        ])
    );
}

impl QnrField for tweedle::Fq {
    // 5
    const QNR: Self = field_new!(
        Self,
        BigInteger256([
            0x30aef343ffffffed,
            0xbcb60a132dafff0b,
            0xffffffffffffffff,
            0x3fffffffffffffff
        ])
    );
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
