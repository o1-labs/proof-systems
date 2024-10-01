use super::backend9;
use super::wasm_fp;
use crate::pasta::Fp;
use ark_ff::PrimeField;

pub struct Fp9Parameters;

impl backend9::FpConstants for Fp9Parameters {
    const MODULUS: [u32; 9] = backend9::from_64x4(Fp::MODULUS.0);
    const R: [u32; 9] = backend9::from_64x4(Fp::R.0);
    const MINV: u64 = Fp::INV;
}
pub type Fp9 = wasm_fp::Fp<Fp9Parameters, 9>;
