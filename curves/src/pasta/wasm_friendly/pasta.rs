use super::{backend9, wasm_fp};
use crate::pasta::{Fp, Fq};
use ark_ff::PrimeField;

pub struct Fp9Parameters;

impl backend9::FpConstants for Fp9Parameters {
    const MODULUS: [u32; 9] = [
        0x1, 0x9698768, 0x133e46e6, 0xd31f812, 0x224, 0x0, 0x0, 0x0, 0x400000,
    ];
    const R: [u32; 9] = [
        0x1fffff81, 0x14a5d367, 0x141ad3c0, 0x1435eec5, 0x1ffeefef, 0x1fffffff, 0x1fffffff,
        0x1fffffff, 0x3fffff,
    ];
    const R2: [u32; 9] = [
        0x3b6a, 0x19c10910, 0x1a6a0188, 0x12a4fd88, 0x634b36d, 0x178792ba, 0x7797a99, 0x1dce5b8a,
        0x3506bd,
    ];
    const MINV: u64 = 0x1fffffff;
}

pub type Fp9 = wasm_fp::Fp<Fp9Parameters, 9>;

impl Fp9 {
    pub fn from_fp(fp: Fp) -> Self {
        backend9::from_bigint_unsafe(super::BigInt::from_digits(backend9::from_64x4(
            fp.into_bigint().0,
        )))
    }
}

impl From<Fp> for Fp9 {
    fn from(fp: Fp) -> Self {
        Fp9::from_fp(fp)
    }
}

pub struct Fq9Parameters;

impl backend9::FpConstants for Fq9Parameters {
    // FIXME @volhovm these are all STUBS and BROKEN, and are for fP9, not fQ9
    const MODULUS: [u32; 9] = [
        0x1, 0x9698768, 0x133e46e6, 0xd31f812, 0x224, 0x0, 0x0, 0x0, 0x400000,
    ];
    const R: [u32; 9] = [
        0x1fffff81, 0x14a5d367, 0x141ad3c0, 0x1435eec5, 0x1ffeefef, 0x1fffffff, 0x1fffffff,
        0x1fffffff, 0x3fffff,
    ];
    const R2: [u32; 9] = [
        0x3b6a, 0x19c10910, 0x1a6a0188, 0x12a4fd88, 0x634b36d, 0x178792ba, 0x7797a99, 0x1dce5b8a,
        0x3506bd,
    ];
    const MINV: u64 = 0x1fffffff;
}

pub type Fq9 = wasm_fp::Fp<Fq9Parameters, 9>;

impl Fq9 {
    pub fn from_fq(fp: Fq) -> Self {
        backend9::from_bigint_unsafe(super::BigInt::from_digits(backend9::from_64x4(
            fp.into_bigint().0,
        )))
    }
}

impl From<Fq> for Fq9 {
    fn from(fp: Fq) -> Self {
        Fq9::from_fq(fp)
    }
}
