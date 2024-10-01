/**
 * Implementation of `FpBackend` for N=9, using 29-bit limbs represented by `u32`s.
 */
use super::bigint32::BigInt;
use super::wasm_fp::{Fp, FpBackend};

type B = [u32; 9];
type B64 = [u64; 9];

const SHIFT: u64 = 29;
const MASK: u32 = (1 << SHIFT) - 1;

const SHIFT64: u64 = SHIFT as u64;
const MASK64: u64 = MASK as u64;

pub trait FpConstants: Send + Sync + 'static + Sized {
    const MODULUS: B;
    const MODULUS64: B64 = {
        let mut modulus64 = [0u64; 9];
        let modulus = Self::MODULUS;
        let mut i = 0;
        while i < 9 {
            modulus64[i] = modulus[i] as u64;
            i += 1;
        }
        modulus64
    };

    /// montgomery params
    /// TODO: compute these
    const R: B; // R = 2^261 mod modulus
    const MINV: u64; // -modulus^(-1) mod 2^29, as a u64
}

#[inline]
fn gte_modulus<FpC: FpConstants>(x: &B) -> bool {
    for i in (0..9).rev() {
        if x[i] > FpC::MODULUS[i] {
            return true;
        } else if x[i] < FpC::MODULUS[i] {
            return false;
        }
    }
    true
}

/// TODO performance ideas to test:
/// - unroll loops
/// - introduce locals for a[i] instead of accessing memory multiple times
/// - only do 1 carry pass at the end, by proving properties of greater-than on uncarried result
/// - use cheaper, approximate greater-than check a[8] > Fp::MODULUS[8]
pub fn add_assign<FpC: FpConstants>(x: &mut B, y: &B) {
    let mut tmp: u32;
    let mut carry: i32 = 0;

    for i in 0..9 {
        tmp = x[i] + y[i] + (carry as u32);
        carry = (tmp as i32) >> SHIFT;
        x[i] = tmp & MASK;
    }

    if gte_modulus::<FpC>(x) {
        carry = 0;
        for i in 0..9 {
            tmp = x[i].wrapping_sub(FpC::MODULUS[i]) + (carry as u32);
            carry = (tmp as i32) >> SHIFT;
            x[i] = tmp & MASK;
        }
    }
}

#[inline]
fn conditional_reduce<FpC: FpConstants>(x: &mut B) {
    if gte_modulus::<FpC>(x) {
        for i in 0..9 {
            x[i] = x[i].wrapping_sub(FpC::MODULUS[i]);
        }
        for i in 1..9 {
            x[i] = x[i] + (((x[i - 1] as i32) >> SHIFT) as u32);
        }
        for i in 0..8 {
            x[i] &= MASK;
        }
    }
}

/// Montgomery multiplication
pub fn mul_assign<FpC: FpConstants>(x: &mut B, y: &B) {
    // load y[i] into local u64s
    // TODO make sure these are locals
    let mut y_local = [0u64; 9];
    for i in 0..9 {
        y_local[i] = y[i] as u64;
    }

    // locals for result
    let mut z = [0u64; 8];
    let mut tmp: u64;

    // main loop, without intermediate carries except for z0
    for i in 0..9 {
        let xi = x[i] as u64;

        // compute qi and carry z0 result to z1 before discarding z0
        tmp = xi * y_local[0];
        let qi = ((tmp & MASK64) * FpC::MINV) & MASK64;
        z[1] += (tmp + qi * FpC::MODULUS64[0]) >> SHIFT64;

        // compute zi and shift in one step
        for j in 1..8 {
            z[j - 1] = z[j] + (xi * y_local[j]) + (qi * FpC::MODULUS64[j]);
        }
        // for j=8 we save an addition since z[8] is never needed
        z[7] = xi * y_local[8] + qi * FpC::MODULUS64[8];
    }

    // final carry pass, store result back into x
    x[0] = (z[0] & MASK64) as u32;
    for i in 1..8 {
        x[i] = (((z[i - 1] >> SHIFT64) + z[i]) & MASK64) as u32;
    }
    x[8] = (z[7] >> SHIFT64) as u32;

    // at this point, x is guaranteed to be less than 2*MODULUS
    // conditionally subtract the modulus to bring it back into the canonical range
    conditional_reduce::<FpC>(x);
}

// implement FpBackend given FpConstants

impl<FpC: FpConstants> FpBackend<9> for FpC {
    const MODULUS: BigInt<9> = BigInt(FpC::MODULUS);
    const ZERO: BigInt<9> = BigInt([0; 9]);
    const ONE: BigInt<9> = BigInt(FpC::R);

    fn add_assign(x: &mut Fp<Self, 9>, y: &Fp<Self, 9>) {
        add_assign::<FpC>(&mut x.0 .0, &y.0 .0);
    }

    fn mul_assign(x: &mut Fp<Self, 9>, y: &Fp<Self, 9>) {
        mul_assign::<Self>(&mut x.0 .0, &y.0 .0);
    }

    fn from_bigint(other: BigInt<9>) -> Option<Fp<Self, 9>> {
        let mut r = [0; 9];
        for i in 0..9 {
            r[i] = other.0[i] as u32;
        }
        if gte_modulus::<Self>(&r) {
            return None;
        }
        Some(Fp(BigInt(r), Default::default()))
    }
}
