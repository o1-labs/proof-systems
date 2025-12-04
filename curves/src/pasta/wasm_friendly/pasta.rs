use super::{
    backend9,
    wasm_fp::{self, FpBackend},
};
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
        let limbs8: [u32; 8] = backend9::from_64x4_to_32x8(fp.into_bigint().0);
        let mut limbs9 = [0u32; 9];
        limbs9[..8].copy_from_slice(&limbs8);

        //println!("from_fp: {:?}, limbs9 {:?}", fp, limbs9);
        backend9::from_bigint_unsafe(super::BigInt::from_digits(limbs9))
    }

    pub fn into_fp(self: Fp9) -> Fp {
        Fp::from_bigint(ark_ff::BigInt(FpBackend::pack(self).try_into().unwrap())).unwrap()
    }
}

impl From<Fp> for Fp9 {
    fn from(fp: Fp) -> Self {
        Fp9::from_fp(fp)
    }
}

impl Into<Fp> for Fp9 {
    fn into(self) -> Fp {
        Fp9::into_fp(self)
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

#[cfg(test)]
mod tests {

    use crate::pasta::{
        wasm_friendly::{
            backend9::{
                add_assign, conditional_reduce, from_32x8, from_32x8_nonconst, gte_modulus,
                is_32x9_shape, mul_assign, to_32x8, FpConstants,
            },
            bigint32_attempt2::BigInt,
            pasta::Fp9Parameters,
            wasm_fp::FpBackend,
            Fp9,
        },
        Fp,
    };
    use ark_ff::{One, UniformRand, Zero};
    use std::str::FromStr;

    // move this into bigint crate?
    #[test]
    fn test_bigint_multiplication_and_modulo() {
        // Test 1: Simple multiplication
        {
            let a = BigInt::<8>::from(123u32);
            let b = BigInt::<8>::from(456u32);
            let expected = BigInt::<8>::from(123u32 * 456u32);
            let result = a * b;
            assert_eq!(result, expected, "Simple multiplication failed");
        }

        // Test 2: Multiplication with larger numbers
        {
            let a = BigInt::<8>::from(0xFFFFFFFFu32);
            let b = BigInt::<8>::from(2u32);
            let expected = BigInt::<8>::from(0x1FFFFFFFEu64);
            let result = a * b;
            assert_eq!(result, expected, "Multiplication with carry failed");
        }

        // Test 3: Simple modulo
        {
            let a = BigInt::<8>::from(10u32);
            let b = BigInt::<8>::from(3u32);
            let expected = BigInt::<8>::from(1u32);
            let result = a % b;
            assert_eq!(result, expected, "Simple modulo failed");
        }

        // Test 4: Modulo with larger numbers
        {
            let a = BigInt::<8>::from(0xFFFFFFFFu32);
            let b = BigInt::<8>::from(0x10000000u32);
            let expected = BigInt::<8>::from(0xFFFFFFFu32);
            let result = a % b;
            assert_eq!(result, expected, "Modulo with larger numbers failed");
        }

        // Test 5: Known values from other libraries
        {
            // These values can be verified with other tools like Python's pow() function
            let base = BigInt::<8>::from_str("123456789012345678901234567890").unwrap();
            let modulus = BigInt::<8>::from_str("987654321098765432109876543210").unwrap();

            // base^2 mod modulus
            let base_squared = (base.clone() * base.clone()) % &modulus;
            let expected = BigInt::<8>::from_str("958236894095823689409582368940").unwrap();
            assert_eq!(
                base_squared, expected,
                "Known value test for (base^2 mod modulus) failed"
            );
        }

        // Test 6: Verify associativity of multiplication
        {
            let a = BigInt::<8>::from(123u32);
            let b = BigInt::<8>::from(456u32);
            let c = BigInt::<8>::from(789u32);

            let result1 = (a.clone() * b.clone()) * c.clone();
            let result2 = a * (b * c);

            assert_eq!(result1, result2, "Multiplication associativity failed");
        }

        // Test 7: Verify distributivity of multiplication over addition
        {
            let a = BigInt::<8>::from(123u32);
            let b = BigInt::<8>::from(456u32);
            let c = BigInt::<8>::from(789u32);

            let result1 = a.clone() * (b.clone() + c.clone());
            let result2 = (a.clone() * b) + (a * c);

            assert_eq!(result1, result2, "Multiplication distributivity failed");
        }

        // Test 8: Modular arithmetic identity: (a * b) % m = ((a % m) * (b % m)) % m
        {
            let a = BigInt::<8>::from(12345u32);
            let b = BigInt::<8>::from(67890u32);
            let m = BigInt::<8>::from(101u32);

            let result1 = (a.clone() * b.clone()) % &m;
            let result2 = ((a % &m) * (b % &m)) % &m;

            assert_eq!(result1, result2, "Modular multiplication identity failed");
        }

        // Test 9: Verify that (a^2) % m works correctly for larger values
        {
            // This can't be close to the field size, has to be 32x4 bits most, since our Bigints overflow.
            let modulus = BigInt::<8>::from_str("11579208923731619542357098500868790").unwrap();
            let mut a = modulus.clone();
            assert!(a.0.digits_mut()[0] >= 1);
            a.0.digits_mut()[0] -= 1; // subtract 1

            let a_squared = (a.clone() * a.clone()) % &modulus;
            let expected = BigInt::<8>::from(1u32);

            assert_eq!(a_squared, expected, "Squaring (p-1) mod p should equal 1");
        }
    }

    #[test]
    fn test_montgomery_constants_consistency() {
        // Test 1: Verify R = 2^261 mod MODULUS
        {
            // Compute 2^261 mod MODULUS
            let modulus =
                BigInt::<8>::from_digits(to_32x8(<Fp9Parameters as FpConstants>::MODULUS));

            // Start with 1 and repeatedly square and multiply
            let mut power_of_2 = BigInt::<8>::ONE;
            for _ in 0..261 {
                power_of_2 = (power_of_2 + power_of_2) % &modulus;
            }

            let r = BigInt::<8>::from_digits(to_32x8(Fp9Parameters::R));
            assert_eq!(r, power_of_2, "R should equal 2^261 mod MODULUS");
        }

        // Test 2: Verify R2 = R^2 mod MODULUS
        // needs twice as much limbs to succeed.
        {
            let extend_array = |arr: [u32; 8]| -> [u32; 16] {
                let mut result = [0u32; 16];
                result[..8].copy_from_slice(&arr);
                result
            };

            let r =
                BigInt::<16>::from_digits(extend_array(to_32x8(<Fp9Parameters as FpConstants>::R)));
            let modulus = BigInt::<16>::from_digits(extend_array(to_32x8(
                <Fp9Parameters as FpConstants>::MODULUS,
            )));

            // Square R and reduce mod MODULUS
            let r_squared = (r.clone() * r) % modulus;

            let r2 = BigInt::<16>::from_digits(extend_array(to_32x8(
                <Fp9Parameters as FpConstants>::R2,
            )));
            assert_eq!(r2, r_squared, "R2 should equal R^2 mod MODULUS");
        }

        // Test 3: Verify MINV is correct: MINV * MODULUS ≡ -1 mod 2^29
        {
            let m0 = <Fp9Parameters as FpConstants>::MODULUS[0] as u64;
            let minv = <Fp9Parameters as FpConstants>::MINV;

            // Check that (MINV * m0) & ((1 << 29) - 1) == (1 << 29) - 1
            // This is equivalent to MINV * m0 ≡ -1 (mod 2^29)
            let result = (minv * m0) & ((1 << 29) - 1);
            let expected = (1 << 29) - 1; // -1 mod 2^29

            assert_eq!(
                result, expected,
                "MINV should satisfy MINV * MODULUS ≡ -1 (mod 2^29)"
            );
        }
    }

    #[test]
    pub fn test_conditional_reduce() {
        // Test 1: Value equal to MODULUS should reduce to 0
        {
            let mut x = <Fp9Parameters as FpConstants>::MODULUS;
            conditional_reduce::<Fp9Parameters>(&mut x);
            let expected = [0u32; 9];
            assert_eq!(x, expected, "MODULUS should reduce to 0");
        }

        // Test 2: Value just below MODULUS should not change
        {
            let mut x = <Fp9Parameters as FpConstants>::MODULUS;
            x[0] -= 1; // Just below MODULUS
            let expected = x.clone();
            conditional_reduce::<Fp9Parameters>(&mut x);
            assert_eq!(x, expected, "Value below MODULUS should not change");
        }

        // Test 3: Value just above MODULUS should reduce correctly
        {
            let mut x = <Fp9Parameters as FpConstants>::MODULUS;
            x[0] += 1; // Just above MODULUS
            conditional_reduce::<Fp9Parameters>(&mut x);
            let expected = [1u32, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(x, expected, "MODULUS+1 should reduce to 1");
        }

        // Test 4: Value at MODULUS + MODULUS - 1 (2*MODULUS - 1)
        {
            let mut x = <Fp9Parameters as FpConstants>::MODULUS;
            for i in 0..9 {
                x[i] = x[i].wrapping_add(<Fp9Parameters as FpConstants>::MODULUS[i]);
            }
            x[0] -= 1; // 2*MODULUS - 1
            conditional_reduce::<Fp9Parameters>(&mut x);

            // Should reduce to MODULUS - 1
            let mut expected = <Fp9Parameters as FpConstants>::MODULUS;
            expected[0] -= 1;
            assert_eq!(x, expected, "2*MODULUS-1 should reduce to MODULUS-1");
        }

        // Test 5: Value with carries needed
        {
            use super::backend9::{MASK, SHIFT};

            let mut x = [0u32; 9];
            x[0] = MASK + 1; // This will need a carry
            x[1] = MASK; // This will overflow after carry

            let expected_before_reduce = [0, 0, 1, 0, 0, 0, 0, 0, 0]; // After normalization
            let mut x_normalized = x;

            // Normalize first (simulate what would happen before conditional_reduce)
            for i in 1..9 {
                x_normalized[i] += ((x_normalized[i - 1] as i32) >> SHIFT) as u32;
                x_normalized[i - 1] &= MASK;
            }

            assert_eq!(x_normalized, expected_before_reduce, "Normalization check");

            // Now test conditional_reduce if this value is >= MODULUS
            if gte_modulus::<Fp9Parameters>(&expected_before_reduce) {
                let mut to_reduce = expected_before_reduce;
                conditional_reduce::<Fp9Parameters>(&mut to_reduce);

                // Calculate expected result manually
                let mut expected = expected_before_reduce;
                for i in 0..9 {
                    expected[i] =
                        expected[i].wrapping_sub(<Fp9Parameters as FpConstants>::MODULUS[i]);
                }
                for i in 1..9 {
                    expected[i] += ((expected[i - 1] as i32) >> SHIFT) as u32;
                    expected[i - 1] &= MASK;
                }

                assert_eq!(
                    to_reduce, expected,
                    "Reduction with carries should work correctly"
                );
            }
        }
    }

    #[test]
    pub fn test_mod_add() {
        {
            let mut b1: [u32; 9] = BigInt::from(7u32).into_digits();
            let b2: [u32; 9] = BigInt::from(9u32).into_digits();
            add_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == BigInt::from(16u32).into_digits())
        }
        {
            let mut b1: [u32; 9] = BigInt::from(7u32).into_digits();
            let b2: [u32; 9] = <Fp9Parameters as FpConstants>::MODULUS;
            add_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == BigInt::from(7u32).into_digits())
        }
        {
            let mut b1: [u32; 9] = <Fp9Parameters as FpConstants>::R;
            let b2: [u32; 9] = <Fp9Parameters as FpConstants>::MODULUS;
            add_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == <Fp9Parameters as FpConstants>::R)
        }
        {
            let mut b1: [u32; 9] = <Fp9Parameters as FpConstants>::R2;
            let b2: [u32; 9] = <Fp9Parameters as FpConstants>::MODULUS;
            add_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == <Fp9Parameters as FpConstants>::R2)
        }
        {
            let mut b1: [u32; 9] = <Fp9Parameters as FpConstants>::MODULUS;
            let b2: [u32; 9] = <Fp9Parameters as FpConstants>::R2;
            add_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == <Fp9Parameters as FpConstants>::R2)
        }
        {
            let mut b1: [u32; 9] = from_32x8(BigInt::from(0x1FFFFFFFu32).into_digits());
            let b2: [u32; 9] = from_32x8(BigInt::from(0x3FFFFFFFu32).into_digits());
            add_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == from_32x8(BigInt::from(1610612734u32).into_digits()));
        }
    }

    #[test]
    pub fn test_montgomery_mult() {
        // R < MODULUS
        {
            assert!(!gte_modulus::<Fp9Parameters>(&Fp9Parameters::R));
        }
        // 1 * R / R = 1
        {
            let mut b1: [u32; 9] = BigInt::from(1u32).into_digits();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == BigInt::from(1u32).into_digits());
        }
        // 12345 * R / R = 12345
        {
            let mut b1: [u32; 9] = BigInt::from(12345u32).into_digits();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == BigInt::from(12345u32).into_digits());
        }
        // <bignum> * R / R = <bignum>
        {
            let mut b1 = from_32x8_nonconst(BigInt::<8>::from_str("12345").unwrap().into_digits());
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }
        // 2^29 * R / R = 2^29
        {
            let mut b1 =
                from_32x8_nonconst(BigInt::<8>::from_str("536870912").unwrap().into_digits());
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }
        // (2^29-1) * R / R = (2^29-1)
        {
            let mut b1 =
                from_32x8_nonconst(BigInt::<8>::from_str("536870911").unwrap().into_digits());
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }
        // (2^29+1) * R / R = (2^29+1)
        {
            let mut b1 =
                from_32x8_nonconst(BigInt::<8>::from_str("536870913").unwrap().into_digits());
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }

        // 2^32 * R / R = 2^32
        {
            let mut b1 =
                from_32x8_nonconst(BigInt::<8>::from_str("4294967296").unwrap().into_digits());
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }
        // (2^32+1) * R / R = (2^32+1)
        {
            let mut b1 =
                from_32x8_nonconst(BigInt::<8>::from_str("4294967297").unwrap().into_digits());
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }

        // (2^64-1) * R / R = (2^64-1)
        {
            let mut b1 = from_32x8_nonconst(
                BigInt::<8>::from_str("18446744073709551615")
                    .unwrap()
                    .into_digits(),
            );
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp);
        }

        // 2^64 * R / R = 2^64
        {
            let mut b1 = from_32x8(
                BigInt::<8>::from_str("18446744073709551616")
                    .unwrap()
                    .into_digits(),
            );
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp, "expected {:?} got {:?}", b1_exp, b1);
        }

        // (2^64+1) * R / R = (2^64+1)
        {
            let mut b1 = from_32x8_nonconst(
                BigInt::<8>::from_str("18446744073709551617")
                    .unwrap()
                    .into_digits(),
            );
            let b1_exp = b1.clone();
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == b1_exp, "expected {:?} got {:?}", b1_exp, b1);
        }

        // 0 * R / R = 0
        {
            let mut b1: [u32; 9] = BigInt::from(0u32).into_digits();
            let b2: [u32; 9] = <Fp9Parameters as FpConstants>::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(b1 == BigInt::from(0u32).into_digits());
        }
        // R * R / R = R
        {
            let mut b1: [u32; 9] = Fp9Parameters::R;
            let b2: [u32; 9] = Fp9Parameters::R;
            assert!(is_32x9_shape(b1));
            assert!(is_32x9_shape(b2));
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            assert!(is_32x9_shape(b1));
            println!("b1 (supposed to be R): {:?}", b1);
            println!("R                    : {:?}", Fp9Parameters::R);
            assert!(b1 == Fp9Parameters::R);
        }
        {
            let mut b1: [u32; 9] = from_32x8(
                BigInt::<9>::from(1u64 << 40).into_digits()[0..8]
                    .try_into()
                    .unwrap(),
            );
            let mut b2: [u32; 9] = from_32x8(
                BigInt::<9>::from(1u64 << 2).into_digits()[0..8]
                    .try_into()
                    .unwrap(),
            );
            let b3: [u32; 9] = from_32x8(
                BigInt::<9>::from(1u64 << 42).into_digits()[0..8]
                    .try_into()
                    .unwrap(),
            );
            let b_one: [u32; 9] = BigInt::from(1u32).into_digits();
            println!("b1 {:?}", b1);
            println!("b2 {:?}", b2);
            println!("b3 {:?}", b3);
            println!("b_one {:?}", b_one);
            mul_assign::<Fp9Parameters>(&mut b1, &<Fp9Parameters as FpConstants>::R2);
            println!("b1 step 1 {:?}", b1);
            mul_assign::<Fp9Parameters>(&mut b2, &<Fp9Parameters as FpConstants>::R2);
            println!("b2 step 2 {:?}", b2);
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            println!("b1 step 3 {:?}", b1);
            mul_assign::<Fp9Parameters>(&mut b1, &b_one);
            println!("b1 step 4 {:?}", b1);
            assert!(b1 == b3);
        }
        {
            let mut b1: [u32; 9] = BigInt::from(1u32).into_digits();
            let b2: [u32; 9] = <Fp9Parameters as FpConstants>::MODULUS;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            println!("{:?}", b1);
            println!("{:?}", b2);
            assert!(b1 == BigInt::from(0u32).into_digits());
        }
        {
            let mut b1: [u32; 9] = Fp9Parameters::R;
            let b2: [u32; 9] = Fp9Parameters::R;
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            println!("b1: {:?}", b1);
            println!("R: {:?}", Fp9Parameters::R);
            assert!(b1 == Fp9Parameters::R);
        }
    }

    #[test]
    pub fn test_fp9_to_from_bigint() {
        let b: BigInt<9> = BigInt::from(123u32);
        let x: Fp9 = Fp9Parameters::from_bigint(b).unwrap();
        let b2 = Fp9Parameters::to_bigint(x);
        assert!(b == b2);
    }

    #[test]
    pub fn test_fp9_fp_conversion() {
        //let x: Fp = rand::random();
        let x: Fp = Fp::from(1u32);
        let z: Fp9 = x.into();
        let x2: Fp = z.into();
        println!("x: {:?}", x);
        println!("x limbs: {:?}", x.0 .0);
        println!("z: {:?}", z);
        println!("z limbs: {:?}", FpBackend::pack(z));
        println!("x2: {:?}", x2);
        assert!(x2 == x);
    }

    #[test]
    fn test_fp_to_fp9_roundtrip() {
        // Test with zero
        let zero = Fp::zero();
        let fp9_zero = Fp9::from_fp(zero);
        let back_to_fp = fp9_zero.into_fp();
        assert_eq!(zero, back_to_fp);

        // Test with one
        let one = Fp::one();
        let fp9_one = Fp9::from_fp(one);
        let back_to_fp = fp9_one.into_fp();
        assert_eq!(one, back_to_fp);

        let v1 = Fp::from(0x1ffffffffffu64);
        println!("{:?}", v1.0);
        let fp9_v1 = Fp9::from_fp(v1);
        println!("{:?}", fp9_v1.0.into_digits());
        let back_to_fp = fp9_v1.into_fp();
        assert_eq!(v1, back_to_fp);

        // Test with random value
        let random = Fp::rand(&mut ark_std::test_rng());
        let fp9_random = Fp9::from_fp(random);
        let back_to_fp = fp9_random.into_fp();
        assert_eq!(random, back_to_fp);
    }

    #[test]
    fn test_from_into_traits() {
        let value = Fp::rand(&mut ark_std::test_rng());

        // Test From<Fp> for Fp9
        let fp9_value: Fp9 = value.into();
        assert_eq!(fp9_value, Fp9::from_fp(value));

        // Test Into<Fp> for Fp9
        let fp_value: Fp = fp9_value.into();
        assert_eq!(fp_value, value);
    }
}
