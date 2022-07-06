pub mod fp_kimchi;
pub mod fp_legacy;
pub mod fq_kimchi;
pub mod fq_legacy;

use crate::poseidon::ArithmeticSpongeParams;
use mina_curves::pasta::{Fp, Fq};
use once_cell::sync::OnceCell;

pub fn fp_kimchi_params() -> ArithmeticSpongeParams<Fp> {
    static P: OnceCell<ArithmeticSpongeParams<Fp>> = OnceCell::new();
    P.get_or_init(fp_kimchi::params).clone()
}

pub fn fp_legacy_params() -> ArithmeticSpongeParams<Fp> {
    static P: OnceCell<ArithmeticSpongeParams<Fp>> = OnceCell::new();
    P.get_or_init(fp_legacy::params).clone()
}

pub fn fq_kimchi_params() -> ArithmeticSpongeParams<Fq> {
    static Q: OnceCell<ArithmeticSpongeParams<Fq>> = OnceCell::new();
    Q.get_or_init(fq_kimchi::params).clone()
}

pub fn fq_legacy_params() -> ArithmeticSpongeParams<Fq> {
    static Q: OnceCell<ArithmeticSpongeParams<Fq>> = OnceCell::new();
    Q.get_or_init(fq_legacy::params).clone()
}
