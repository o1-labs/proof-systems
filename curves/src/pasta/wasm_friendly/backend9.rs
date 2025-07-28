/**
 * Implementation of `FpBackend` for N=9, using 29-bit limbs represented by `u32`s.
 */
use super::bigint32_attempt2::BigInt;
use super::wasm_fp::{Fp, FpBackend};

type B = [u32; 9];
type B64 = [u64; 9];

const SHIFT: u32 = 29;
const MASK: u32 = (1 << SHIFT) - 1;

const SHIFT64: u64 = SHIFT as u64;
const MASK64: u64 = MASK as u64;

pub const fn from_64x4(pa: [u64; 4]) -> [u32; 9] {
    let mut p = [0u32; 9];
    p[0] = (pa[0] & MASK64) as u32;
    p[1] = ((pa[0] >> 29) & MASK64) as u32;
    p[2] = (((pa[0] >> 58) | (pa[1] << 6)) & MASK64) as u32;
    p[3] = ((pa[1] >> 23) & MASK64) as u32;
    p[4] = (((pa[1] >> 52) | (pa[2] << 12)) & MASK64) as u32;
    p[5] = ((pa[2] >> 17) & MASK64) as u32;
    p[6] = (((pa[2] >> 46) | (pa[3] << 18)) & MASK64) as u32;
    p[7] = ((pa[3] >> 11) & MASK64) as u32;
    p[8] = (pa[3] >> 40) as u32;
    p
}

pub const fn to_64x4(pa: [u32; 9]) -> [u64; 4] {
    let mut p = [0u64; 4];
    p[0] = pa[0] as u64;
    p[0] |= (pa[1] as u64) << 29;
    p[0] |= (pa[2] as u64) << 58;
    p[1] = (pa[2] as u64) >> 6;
    p[1] |= (pa[3] as u64) << 23;
    p[1] |= (pa[4] as u64) << 52;
    p[2] = (pa[4] as u64) >> 12;
    p[2] |= (pa[5] as u64) << 17;
    p[2] |= (pa[6] as u64) << 46;
    p[3] = (pa[6] as u64) >> 18;
    p[3] |= (pa[7] as u64) << 11;
    p[3] |= (pa[8] as u64) << 40;
    p
}

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
    const R2: B; // R^2 mod modulus
    const MINV: u64; // -modulus^(-1) mod 2^29, as a u64
}

#[inline]
fn gte_modulus<FpC: FpConstants>(x: &B) -> bool {
    for i in (0..9).rev() {
        // don't fix warning -- that makes it 15% slower!
        #[allow(clippy::comparison_chain)]
        if x[i] > FpC::MODULUS[i] {
            return true;
        } else if x[i] < FpC::MODULUS[i] {
            return false;
        }
    }
    true
}

// TODO performance ideas to test:
// - unroll loops
// - introduce locals for a[i] instead of accessing memory multiple times
// - only do 1 carry pass at the end, by proving properties of greater-than on uncarried result
// - use cheaper, approximate greater-than check a[8] > Fp::MODULUS[8]
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
        #[allow(clippy::needless_range_loop)]
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
        #[allow(clippy::needless_range_loop)]
        for i in 0..9 {
            x[i] = x[i].wrapping_sub(FpC::MODULUS[i]);
        }
        #[allow(clippy::needless_range_loop)]
        for i in 1..9 {
            x[i] += ((x[i - 1] as i32) >> SHIFT) as u32;
        }
        #[allow(clippy::needless_range_loop)]
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
    #[allow(clippy::needless_range_loop)]
    for i in 0..9 {
        let xi = x[i] as u64;

        // compute qi and carry z0 result to z1 before discarding z0
        tmp = (xi * y_local[0]) + z[0];
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

pub fn from_bigint_unsafe<FpC: FpConstants>(x: BigInt<9>) -> Fp<FpC, 9> {
    let mut r = Into::<[u32; 9]>::into(x);
    // convert to montgomery form
    mul_assign::<FpC>(&mut r, &FpC::R2);
    Fp(BigInt::from_digits(r), Default::default())
}

impl<FpC: FpConstants> FpBackend<9> for FpC {
    const MODULUS: BigInt<9> = BigInt::from_digits(Self::MODULUS);
    const ZERO: BigInt<9> = BigInt::from_digits([0; 9]);
    const ONE: BigInt<9> = BigInt::from_digits(Self::R);

    fn add_assign(x: &mut Fp<Self, 9>, y: &Fp<Self, 9>) {
        todo!()
    }

    fn mul_assign(x: &mut Fp<Self, 9>, y: &Fp<Self, 9>) {
        todo!()
    }

    fn from_bigint(x: BigInt<9>) -> Option<Fp<Self, 9>> {
        if gte_modulus::<Self>(&Into::<[u32; 9]>::into(x)) {
            None
        } else {
            Some(from_bigint_unsafe(x))
        }
    }

    fn to_bigint(x: Fp<Self, 9>) -> BigInt<9> {
        todo!()
        //let one = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        //let mut r = x.0 .0;
        //// convert back from montgomery form
        //mul_assign::<Self>(&mut r, &one);
        //BigInt::from_digits(r)
    }

    fn pack(x: Fp<Self, 9>) -> Vec<u64> {
        todo!()
        //let x = Self::to_bigint(x).0;
        //let x64 = to_64x4(x);
        //let mut res = Vec::with_capacity(4);
        //for limb in x64.iter() {
        //    res.push(*limb);
        //}
        //res
    }
}
