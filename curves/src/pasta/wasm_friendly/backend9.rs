/**
 * Implementation of `FpBackend` for N=9, using 29-bit limbs represented by `u32`s.
 */
use super::bigint32_attempt2::BigInt;
use super::wasm_fp::{Fp, FpBackend};

type B = [u32; 9];
type B64 = [u64; 9];

pub const SHIFT: u32 = 29;
pub const MASK: u32 = (1 << SHIFT) - 1;

pub const SHIFT64: u64 = SHIFT as u64;
pub const MASK64: u64 = MASK as u64;

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

pub const fn from_64x4_to_32x8(p: [u64; 4]) -> [u32; 8] {
    let mut pa = [0u32; 8];
    pa[0] = p[0] as u32;
    pa[1] = (p[0] >> 32) as u32;
    pa[2] = p[1] as u32;
    pa[3] = (p[1] >> 32) as u32;
    pa[4] = p[2] as u32;
    pa[5] = (p[2] >> 32) as u32;
    pa[6] = p[3] as u32;
    pa[7] = (p[3] >> 32) as u32;
    pa
}

pub const fn from_32x8_to_64x4(pa: [u32; 8]) -> [u64; 4] {
    let mut p = [0u64; 4];
    p[0] = (pa[0] as u64) | ((pa[1] as u64) << 32);
    p[1] = (pa[2] as u64) | ((pa[3] as u64) << 32);
    p[2] = (pa[4] as u64) | ((pa[5] as u64) << 32);
    p[3] = (pa[6] as u64) | ((pa[7] as u64) << 32);
    p
}

// Converts from "normal" 32 bit bignum limb format to the 32x9 with 29 bit limbs.
pub const fn from_32x8(pa: [u32; 8]) -> [u32; 9] {
    let p = from_32x8_to_64x4(pa);
    let res = from_64x4(p);
    assert!(is_32x9_shape(res));
    res
}

// Converts from "normal" 32 bit bignum limb format to the 32x9 with 29 bit limbs.
pub fn from_32x8_nonconst(pa: [u32; 8]) -> [u32; 9] {
    let p = from_32x8_to_64x4(pa);
    let res = from_64x4(p);
    if !is_32x9_shape(res) {
        println!("pa: {:?}", pa);
        println!("p: {:?}", p);
        println!("res: {:?}", res);
        panic!();
    }
    res
}

// Converts from 32x9 with 29 bit limbs back to "normal" 32 bit bignum limb format.
pub fn to_32x8(limbs29: [u32; 9]) -> [u32; 8] {
    // First convert to 64x4 format
    let limbs64 = to_64x4(limbs29);

    // Then split each 64-bit limb into two 32-bit limbs
    let mut result = [0u32; 8];
    result[0] = limbs64[0] as u32;
    result[1] = (limbs64[0] >> 32) as u32;
    result[2] = limbs64[1] as u32;
    result[3] = (limbs64[1] >> 32) as u32;
    result[4] = limbs64[2] as u32;
    result[5] = (limbs64[2] >> 32) as u32;
    result[6] = limbs64[3] as u32;
    result[7] = (limbs64[3] >> 32) as u32;

    result
}

/// Checks if the number satisfies 32x9 shape (each limb 29 bits).
pub const fn is_32x9_shape(pa: [u32; 9]) -> bool {
    let b0 = (pa[0] >> 29) == 0;
    let b1 = (pa[1] >> 29) == 0;
    let b2 = (pa[2] >> 29) == 0;
    let b3 = (pa[3] >> 29) == 0;
    let b4 = (pa[4] >> 29) == 0;
    let b5 = (pa[5] >> 29) == 0;
    let b6 = (pa[6] >> 29) == 0;
    let b7 = (pa[7] >> 29) == 0;
    let b8 = (pa[8] >> 29) == 0;

    b0 && b1 && b2 && b3 && b4 && b5 && b6 && b7 && b8
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
    const MINV: u64; // - modulus^(-1) mod 2^29, as a u64
}

#[inline]
pub fn gte_modulus<FpC: FpConstants>(x: &B) -> bool {
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
/// Performs modular addition: x = (x + y) mod p
///
/// This function adds two field elements and stores the result in the first operand.
/// The result is reduced to ensure it remains within the canonical range [0, p-1].
///
/// # Parameters
/// * `x` - First operand, modified in-place to store the result
/// * `y` - Second operand to add
///
/// # Type Parameters
/// * `FpC` - Type implementing the FpConstants trait that defines the modulus
///
/// # Implementation Notes
/// - First performs the addition with carry propagation
/// - Then conditionally subtracts the modulus if the result is greater than or equal to it
///
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
pub fn conditional_reduce<FpC: FpConstants>(x: &mut B) {
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

// See: https://github.com/mitschabaude/montgomery/blob/4f1405073aef60b469a0fcd45ff9166f8de4a4bf/src/wasm/multiply-montgomery.ts#L58
/// Performs Montgomery multiplication: x = (x * y * R^-1) mod p
///
/// This function multiplies two field elements in Montgomery form and stores
/// the result in the first operand. The implementation uses the CIOS (Coarsely
/// Integrated Operand Scanning) method for Montgomery multiplication.
///
/// # Parameters
/// * `x` - First operand, modified in-place to store the result
/// * `y` - Second operand
///
/// # Type Parameters
/// * `FpC` - Type implementing the FpConstants trait that defines the modulus
///   and Montgomery reduction parameters
///
/// # Implementation Notes
/// - Uses a 9-limb representation for intermediate calculations
/// - Performs a conditional reduction at the end to ensure the result is in
///   the canonical range [0, p-1]
/// - Optimized to minimize carry operations in the main loop
pub fn mul_assign_orig<FpC: FpConstants>(x: &mut B, y: &B) {
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

        // tmp = x[i] * y[0] + z[0]     (mod u64)
        // qi = lowest64bits(lowest29bits(x[i] * y[0] + z[0]) * MINV)
        // compute qi and carry z0 result to z1 before discarding z0
        tmp = (xi * y_local[0]) + z[0];
        let qi = ((tmp & MASK64) * FpC::MINV) & MASK64;
        z[1] += (tmp + qi * FpC::MODULUS64[0]) >> SHIFT64;

        // compute zi and shift in one step
        for j in 0..7 {
            z[j] = z[j + 1] + (xi * y_local[j + 1]) + (qi * FpC::MODULUS64[j + 1]);
        }

        // for j=8 we save an addition since z[8] is never needed
        z[7] = xi * y_local[8] + qi * FpC::MODULUS64[8];
    }

    println!("before carry pass: z = {:?}", z);

    // final carry pass, store result back into x
    x[0] = (z[0] & MASK64) as u32;
    for i in 1..8 {
        x[i] = (((z[i - 1] >> SHIFT64) + z[i]) & MASK64) as u32;
    }
    x[8] = (z[7] >> SHIFT64) as u32;

    println!("before conditional reduce: {:?}", x);

    // at this point, x is guaranteed to be less than 2*MODULUS
    // conditionally subtract the modulus to bring it back into the canonical range
    conditional_reduce::<FpC>(x);
}

// FIXME implementation that uses 9 limbs for z, check it
pub fn mul_assign<FpC: FpConstants>(x: &mut B, y: &B) {
    // load y[i] into local u64s
    let mut y_local = [0u64; 9];
    for i in 0..9 {
        y_local[i] = y[i] as u64;
    }

    let mut z = [0u64; 9];

    // main loop
    for i in 0..9 {
        let xi = x[i] as u64;

        // compute qi and first multiplication
        let tmp = (xi * y_local[0]) + z[0];
        let qi = ((tmp & MASK64) * FpC::MINV) & MASK64;

        // carry from first step
        let mut carry = (tmp + qi * FpC::MODULUS64[0]) >> SHIFT64;

        // compute remaining steps with proper carry propagation
        for j in 1..9 {
            let t = z[j] + (xi * y_local[j]) + (qi * FpC::MODULUS64[j]) + carry;
            z[j - 1] = t & MASK64;
            carry = t >> SHIFT64;
        }

        // store final carry
        z[8] = carry;
    }

    // final carry pass, store result back into x
    let mut carry = 0u64;
    for i in 0..9 {
        let t = z[i] + carry;
        x[i] = (t & MASK64) as u32;
        carry = t >> SHIFT64;
    }

    // at this point, x is guaranteed to be less than 2*MODULUS
    // conditionally subtract the modulus to bring it back into the canonical range
    conditional_reduce::<FpC>(x);
}

// implement FpBackend given FpConstants

/// Converts a bigint of 9 limbs, of 32x8 shape, into a field element.
/// MUST have `x[8] == 0`.
pub fn from_bigint_unsafe<FpC: FpConstants>(x: BigInt<9>) -> Fp<FpC, 9> {
    let r: [u32; 9] = x.into_digits();
    //assert!(r[8] == 0, "from_bigint_unsafe: bigint exceeds 256 bits");
    let mut r = from_32x8(r[0..8].try_into().unwrap());
    //assert!(is_32x9_shape(r));
    // convert to montgomery form
    mul_assign::<FpC>(&mut r, &FpC::R2);
    //assert!(is_32x9_shape(r));
    Fp(BigInt::from_digits(r), Default::default())
}

impl<FpC: FpConstants> FpBackend<9> for FpC {
    const MODULUS: BigInt<9> = BigInt::from_digits(Self::MODULUS);
    const ZERO: BigInt<9> = BigInt::from_digits([0; 9]);
    const ONE: BigInt<9> = BigInt::from_digits(Self::R);

    fn add_assign(x: &mut Fp<Self, 9>, y: &Fp<Self, 9>) {
        //panic!("test1");
        //std::ops::AddAssign::add_assign(x, y)
        add_assign::<FpC>(x.0.as_digits_mut(), &y.0.into_digits())
    }

    fn mul_assign(x: &mut Fp<Self, 9>, y: &Fp<Self, 9>) {
        mul_assign::<FpC>(x.0.as_digits_mut(), &y.0.into_digits())
    }

    fn from_bigint(x: BigInt<9>) -> Option<Fp<Self, 9>> {
        if gte_modulus::<Self>(&Into::<[u32; 9]>::into(x)) {
            None
        } else {
            Some(from_bigint_unsafe(x))
        }
    }

    /// Return a "normal" bigint
    fn to_bigint(x: Fp<Self, 9>) -> BigInt<9> {
        //assert!(is_32x9_shape(x.0.into_digits()));
        let one: [u32; 9] = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut r = x.0.into_digits();
        // convert back from montgomery form
        mul_assign::<Self>(&mut r, &one);
        let repr: [u32; 8] = to_32x8(r);
        let mut extended_repr = [0u32; 9];
        extended_repr[..8].copy_from_slice(&repr);
        BigInt::from_digits(extended_repr)
    }

    fn pack(x: Fp<Self, 9>) -> Vec<u64> {
        let x = Self::to_bigint(x).into_digits();
        let x64 = from_32x8_to_64x4(x[0..8].try_into().unwrap());
        let mut res = Vec::with_capacity(4);
        for limb in x64.iter() {
            res.push(*limb);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_64_32_conversion_identity() {
        // Test with various inputs
        let test_cases = [
            [0u64; 4],
            [1u64, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [0, 0, 0, 1],
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX],
            [
                0x123456789ABCDEF0,
                0xFEDCBA9876543210,
                0xAAAABBBBCCCCDDDD,
                0x1122334455667788,
            ],
        ];

        for input in &test_cases {
            // Convert to 9x32-bit representation and back
            let intermediate = from_64x4(*input);
            let result = to_64x4(intermediate);

            // Check if the round-trip conversion preserves the original value
            assert_eq!(
                result, *input,
                "Conversion failed for input: {:?}, got: {:?}",
                input, result
            );
        }

        // Test with random inputs
        for _ in 0..100 {
            let random_input = [
                rand::random::<u64>(),
                rand::random::<u64>(),
                rand::random::<u64>(),
                rand::random::<u64>(),
            ];

            let intermediate = from_64x4(random_input);
            let result = to_64x4(intermediate);

            assert!(
                is_32x9_shape(intermediate),
                "from_64x4 does not pass the is_32x9_shape check"
            );

            assert_eq!(
                result, random_input,
                "Conversion failed for random input: {:?}",
                random_input
            );
        }

        {
            let out_of_shape: [u32; 9] = [
                1 << 31,
                1 << 31,
                1 << 31,
                1 << 31,
                1 << 31,
                1 << 31,
                1 << 31,
                1 << 31,
                1 << 31,
            ];

            assert!(
                !is_32x9_shape(out_of_shape),
                "out of shape must NOT pass is_32x9_shape check"
            );
        }
    }
}
