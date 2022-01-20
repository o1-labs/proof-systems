use ark_ff::{field_new, SquareRootField};
use mina_curves::pasta::{Fp, Fq};

pub trait QnrField: SquareRootField {
    const QNR: Self;
}

impl QnrField for Fp {
    // 5
    const QNR: Self = field_new!(Fp, "5");
}

impl QnrField for Fq {
    // 5
    const QNR: Self = field_new!(Fq, "5");
}
