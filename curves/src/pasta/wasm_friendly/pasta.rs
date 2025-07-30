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
        backend9::from_bigint_unsafe(super::BigInt::from_digits(backend9::from_64x4(
            fp.into_bigint().0,
        )))
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
            backend9::{add_assign, from_32x8, mul_assign, FpConstants},
            bigint32_attempt2::BigInt,
            pasta::Fp9Parameters,
            wasm_fp::FpBackend,
            Fp9,
        },
        Fp,
    };

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
    }

    #[test]
    pub fn test_montgomery_mult() {
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
            mul_assign::<Fp9Parameters>(&mut b1, &b2);
            println!("b1: {:?}", b1);
            println!("R: {:?}", Fp9Parameters::R);
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
}
