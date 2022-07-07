pub mod fp_kimchi;
pub mod fp_legacy;
pub mod fq_kimchi;
pub mod fq_legacy;

use crate::poseidon::ArithmeticSpongeParams;
use mina_curves::pasta::{Fp, Fq};
use once_cell::sync::OnceCell;

pub fn fp_kimchi_params() -> &'static ArithmeticSpongeParams<Fp> {
    static P: OnceCell<ArithmeticSpongeParams<Fp>> = OnceCell::new();
    P.get_or_init(fp_kimchi::params)
}

pub fn fp_legacy_params() -> &'static ArithmeticSpongeParams<Fp> {
    static P: OnceCell<ArithmeticSpongeParams<Fp>> = OnceCell::new();
    P.get_or_init(fp_legacy::params)
}

pub fn fq_kimchi_params() -> &'static ArithmeticSpongeParams<Fq> {
    static Q: OnceCell<ArithmeticSpongeParams<Fq>> = OnceCell::new();
    Q.get_or_init(fq_kimchi::params)
}

pub fn fq_legacy_params() -> &'static ArithmeticSpongeParams<Fq> {
    static Q: OnceCell<ArithmeticSpongeParams<Fq>> = OnceCell::new();
    Q.get_or_init(fq_legacy::params)
}
