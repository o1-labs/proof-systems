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

        assert!(false);

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
