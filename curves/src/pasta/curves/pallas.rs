use crate::pasta::{wasm_friendly::BigInt, *};
use ark_ec::{
    models::short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{MontFp, Zero};
use std::marker::PhantomData;

/// G_GENERATOR_X =
/// 1
pub const G_GENERATOR_X: Fp = MontFp!("1");

/// G1_GENERATOR_Y =
/// 12418654782883325593414442427049395787963493412651469444558597405572177144507
pub const G_GENERATOR_Y: Fp =
    MontFp!("12418654782883325593414442427049395787963493412651469444558597405572177144507");

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PallasParameters;

impl CurveConfig for PallasParameters {
    type BaseField = Fp;

    type ScalarField = Fq;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fq = MontFp!("1");
}

pub type Pallas = Affine<PallasParameters>;

pub type ProjectivePallas = Projective<PallasParameters>;

impl SWCurveConfig for PallasParameters {
    const COEFF_A: Self::BaseField = MontFp!("0");

    const COEFF_B: Self::BaseField = MontFp!("5");

    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

impl PallasParameters {
    #[inline(always)]
    pub fn mul_by_a(
        _: &<PallasParameters as CurveConfig>::BaseField,
    ) -> <PallasParameters as CurveConfig>::BaseField {
        <PallasParameters as CurveConfig>::BaseField::zero()
    }
}

/// legacy curve, a copy of the normal curve to support legacy sponge params
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct LegacyPallasParameters;

impl CurveConfig for LegacyPallasParameters {
    type BaseField = <PallasParameters as CurveConfig>::BaseField;

    type ScalarField = <PallasParameters as CurveConfig>::ScalarField;

    const COFACTOR: &'static [u64] = <PallasParameters as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Self::ScalarField = <PallasParameters as CurveConfig>::COFACTOR_INV;
}

impl SWCurveConfig for LegacyPallasParameters {
    const COEFF_A: Self::BaseField = <PallasParameters as SWCurveConfig>::COEFF_A;

    const COEFF_B: Self::BaseField = <PallasParameters as SWCurveConfig>::COEFF_B;

    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

pub type LegacyPallas = Affine<LegacyPallasParameters>;

////////////////////////////////////////////////////////////////////////////
// WASM experimentation
////////////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct WasmPallasParameters;

impl CurveConfig for WasmPallasParameters {
    type BaseField = crate::pasta::wasm_friendly::Fp9;

    type ScalarField = crate::pasta::wasm_friendly::Fq9; // FIXME must be Fq9 of course

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = 1
    // FIXME
    const COFACTOR_INV: crate::pasta::wasm_friendly::Fq9 =
        crate::pasta::wasm_friendly::Fp(BigInt::ONE, PhantomData);
}

pub type WasmPallas = Affine<WasmPallasParameters>;

pub type WasmProjectivePallas = Projective<WasmPallasParameters>;

//pub const G_GENERATOR_Y: Fp =
//    MontFp!("12418654782883325593414442427049395787963493412651469444558597405572177144507");a
//
//    BigInt::from_digits([
//        0x0, 0x1B74B5A3, 0x0A12937C, 0x53DFA9F0, 0x6378EE54, 0x8F655BD4, 0x333D4771, 0x19CF7A23,
//        0xCAED2ABB,
//    ]),
pub const G_GENERATOR_Y_WASM: crate::pasta::wasm_friendly::Fp9 = crate::pasta::wasm_friendly::Fp(
    BigInt::from_digits(crate::pasta::wasm_friendly::backend9::from_64x4([
        0xBBA2DEAC32A7FC19,
        0x1774D3334DB556F8,
        0x45EE87360F9AFD35,
        0xC73921A03A5B47B1,
    ])),
    PhantomData,
);

impl SWCurveConfig for WasmPallasParameters {
    const COEFF_A: Self::BaseField = crate::pasta::wasm_friendly::Fp(BigInt::ZERO, PhantomData);

    const COEFF_B: Self::BaseField = crate::pasta::wasm_friendly::Fp(BigInt::FIVE, PhantomData);

    const GENERATOR: Affine<Self> = Affine::new_unchecked(
        crate::pasta::wasm_friendly::Fp(BigInt::ONE, PhantomData),
        crate::pasta::wasm_friendly::Fp(BigInt::ZERO, PhantomData),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pasta::{
        wasm_friendly::{wasm_fp::FpBackend, Fp9},
        Fp,
    };

    #[test]
    pub fn test_wasm_curve_basic_ops() {
        // Constants with large bit sizes
        let large_a: u32 = 0x1FFFFFFF; // 29 bits (max for a limb)
        let large_b: u32 = 0x3FFFFFFF; // 30 bits

        // Test Fp9 operations with large numbers
        {
            // Test conversion between Fp and Fp9 with large numbers
            let x: Fp = Fp::from(large_a);
            let x_fp9: Fp9 = x.into();
            let x_back: Fp = x_fp9.into();
            assert_eq!(
                x, x_back,
                "Conversion between Fp and Fp9 with large numbers failed"
            );

            // Create Fp9 elements with large components
            let a: Fp = Fp::from(large_a);
            let b: Fp = Fp::from(large_b);
            let a_fp9: Fp9 = a.into();
            let b_fp9: Fp9 = b.into();

            // Test Fp9 addition with large numbers
            let sum_fp9 = a_fp9 + b_fp9;
            let expected_sum_fp9: Fp9 = (a + b).into();
            assert_eq!(
                sum_fp9, expected_sum_fp9,
                "Fp9 addition with large numbers failed"
            );

            // Test Fp9 multiplication with large numbers
            let prod_fp9 = a_fp9 * b_fp9;
            let expected_prod_fp9: Fp9 = (a * b).into();
            assert_eq!(
                prod_fp9, expected_prod_fp9,
                "Fp9 multiplication with large numbers failed"
            );

            // Test Fp9 squaring with large numbers
            let square_fp9 = a_fp9 * a_fp9;
            let expected_square_fp9: Fp9 = (a * a).into();
            assert_eq!(
                square_fp9, expected_square_fp9,
                "Fp9 squaring with large numbers failed"
            );
        }

        // Test consistency between Fp and Fp9 operations with large numbers
        {
            // Create random large Fp elements
            let x: Fp = Fp::from(large_a) * Fp::from(0x12345678u64);
            let y: Fp = Fp::from(large_b) * Fp::from(0x87654321u64);

            // Compute product in Fp
            let z_fp: Fp = x * y;

            // Compute product in Fp9 and convert back
            let x_fp9: Fp9 = x.into();
            let y_fp9: Fp9 = y.into();
            let z_fp9: Fp9 = x_fp9 * y_fp9;
            let z_fp_from_fp9: Fp = z_fp9.into();

            // Results should be equal
            assert_eq!(
                z_fp, z_fp_from_fp9,
                "Inconsistency between Fp and Fp9 multiplication with large numbers"
            );

            // Test multiple operations in sequence
            let result_fp = ((x * y) + x) * y;
            let result_fp9: Fp = (((x_fp9 * y_fp9) + x_fp9) * y_fp9).into();
            assert_eq!(
                result_fp, result_fp9,
                "Complex operation sequence inconsistent between Fp and Fp9"
            );
        }

        // Test with numbers that would span multiple limbs
        {
            // Create Fp9 with non-trivial structure (not just embedding of Fp)
            // This would require knowledge of how to construct a general Fp9 element

            // For now, test with large random values
            let r1: Fp = rand::random();
            let r2: Fp = rand::random();

            // Ensure these are large values by multiplying with our large constants
            let large_r1 = r1 * Fp::from(large_a);
            let large_r2 = r2 * Fp::from(large_b);

            // Convert to Fp9
            let r1_fp9: Fp9 = large_r1.into();
            let r2_fp9: Fp9 = large_r2.into();

            // Test operations
            let sum_fp9 = r1_fp9 + r2_fp9;
            let prod_fp9 = r1_fp9 * r2_fp9;

            // Verify conversion back
            let sum_fp: Fp = sum_fp9.into();
            let prod_fp: Fp = prod_fp9.into();

            assert_eq!(
                sum_fp,
                large_r1 + large_r2,
                "Sum conversion inconsistent with large numbers"
            );
            assert_eq!(
                prod_fp,
                large_r1 * large_r2,
                "Product conversion inconsistent with large numbers"
            );
        }
    }

    #[test]
    pub fn test_naive_wasm_curve_basic_ops() {
        {
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

        {
            let x: Fp = rand::random();
            let y: Fp = rand::random();
            let z: Fp = x * y;
        }

        {
            let x: Fp = rand::random();
            let y: Fp = rand::random();
            let x_fp9: Fp9 = x.into();
            let y_fp9: Fp9 = y.into();
        }

        {
            let x: Fp = rand::random();
            let y: Fp = rand::random();

            let x_fp9: Fp9 = From::from(x);
            let y_fp9: Fp9 = From::from(y);
            let z_fp9: Fp9 = x_fp9 * y_fp9;
        }

        {
            let x: Fp = rand::random();
            let y: Fp = rand::random();
            let z: Fp = x * y;
            let z: Fp = z * x;
        }

        {
            let x: Fp = rand::random();
            let y: Fp = rand::random();
            let x_fp9: Fp9 = From::from(x);
            let y_fp9: Fp9 = From::from(y);
            let z_fp9: Fp9 = x_fp9 * y_fp9;
            let z_fp9: Fp9 = z_fp9 * x_fp9;
        }

        {
            let x: Fp = rand::random();
            let y: Fp = rand::random();
            let z: Fp = x * y;
            let z: Fp = z * x;
            let z: Fp = z * y;
            let z: Fp = z * x;
        }
    }
}
