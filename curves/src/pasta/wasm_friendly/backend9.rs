/**
 * Implementation of `FpBackend` for N=9, using 29-bit limbs represented by `u32`s.
 */
use super::wasm_fp::{Fp, FpBackend};

type B = [u32; 9];

const SHIFT: u64 = 29;
const MASK: u32 = (1 << SHIFT) - 1;
const MASK64: u64 = MASK as u64;
const TOTAL_BITS: u64 = 9 * SHIFT; // 261

pub trait FpConstants {
    const MODULUS: B;
    const R: B; // R = 2^261 % modulus
    const R2: B; // R^2 % modulus
    const MINV: u64; // -modulus^{-1} mod 2^32, as a u64
}

#[inline]
fn gt_modulus<Fp: FpConstants>(a: B) -> bool {
    for i in (0..9).rev() {
        if a[i] > Fp::MODULUS[i] {
            return true;
        } else if a[i] < Fp::MODULUS[i] {
            return false;
        }
    }
    false
}

/// TODO performance ideas to test:
/// - unroll loops
/// - introduce locals for a[i] instead of accessing memory multiple times
/// - only do 1 carry pass at the end, by proving properties of greater-than on uncarried result
/// - use cheaper, approximate greater-than check a[8] > Fp::MODULUS[8]
pub fn add_assign<Fp: FpConstants>(mut a: B, b: B) {
    let mut tmp: u32;
    let mut carry: u32 = 0;

    for i in 0..9 {
        tmp = a[i] + b[i] + carry;
        carry = tmp >> SHIFT;
        a[i] = tmp & MASK;
    }

    if gt_modulus::<Fp>(a) {
        carry = 0;
        for i in 0..9 {
            tmp = a[i] - Fp::MODULUS[i] + carry;
            carry = tmp >> SHIFT;
            a[i] = tmp & MASK;
        }
    }
}
