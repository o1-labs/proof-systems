use algebra::{
    BigInteger256,
    BigInteger384,
    field_new,
    SquareRootField,
    bn_382,
    tweedle,
};

pub trait QnrField : SquareRootField {
    const QNR : Self;
}

impl QnrField for bn_382::Fp {
    // 7
    const QNR : Self = field_new!(
        Self,
        BigInteger384([0xffffffffffffffcf, 0xffffffb67daf6367, 0xdc87071c715188df, 0x718ba6243a5346c8, 0x4fa46fc531ce56d5, 0x1b21bac71c8e0dbc])
    );
}

impl QnrField for bn_382::Fq {
    // 7
    const QNR : Self = field_new!(
        Self,
        BigInteger384([0xffffffffffffffcf, 0xffffffb67daf6367, 0x7b5eb425ec6cb67f, 0x718ba6243a5346b6, 0x4fa46fc531ce56d5, 0x1b21bac71c8e0dbc])
    );
}

impl QnrField for tweedle::Fp {
    // 5
    const QNR : Self = field_new!(
        Self,
        BigInteger256([0x8388339ffffffed, 0xbcb60a12f74c5739, 0xffffffffffffffff, 0x3fffffffffffffff])
    );
}

impl QnrField for tweedle::Fq {
    // 5
    const QNR : Self = field_new!(
        Self,
        BigInteger256([0x30aef343ffffffed, 0xbcb60a132dafff0b, 0xffffffffffffffff, 0x3fffffffffffffff])
    );
}
